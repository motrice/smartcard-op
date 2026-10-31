// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/motrice/smartcard-op/internal/adapters/keys"
	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrUnknownAuthRequest means the authorization request has expired or
	// never existed. In practice the user took too long, or the process was
	// replaced mid-login.
	ErrUnknownAuthRequest = errors.New("unknown authorization request")
	// ErrUnsupportedFeature wraps every endpoint this provider deliberately
	// does not serve.
	ErrUnsupportedFeature = errors.New("unsupported feature")
)

const (
	// authRequestLifetime is how long an unfinished authorization request
	// is kept. It bounds how long a user may dawdle over the card dialog.
	authRequestLifetime = 10 * time.Minute
	// identityLifetime is how long a completed identity is retained so that
	// /userinfo can answer after the code exchange. It must outlive the
	// access token.
	identityLifetime = 15 * time.Minute
	// accessTokenLifetime matches the id_token's.
	accessTokenLifetime = 5 * time.Minute
)

func errUnsupported(feature string) error {
	return fmt.Errorf("%w: %s is not supported by this provider", ErrUnsupportedFeature, feature)
}

// StorageConfig is what the storage needs in order to serve the provider.
type StorageConfig struct {
	// Keys holds the signing key and the keys published at /keys.
	Keys *keys.Set
	// Client registers the one relying party, Zitadel.
	Client ClientConfig
	// SyntheticEmailDomain is the domain synthetic addresses are placed
	// under. See NewClaims for why they exist.
	SyntheticEmailDomain string
	// AllowInsecureForTests relaxes the requirement that every redirect uri
	// and the login url be https, so that an in-process test can drive the
	// flow over httptest's plaintext listeners.
	//
	// It must never be set in a deployed configuration. The name is
	// deliberately awkward so that it cannot slip through a review of a
	// configuration file unnoticed.
	AllowInsecureForTests bool
}

// Storage backs the OpenID Provider.
//
// State is held in memory: an authorization request lives about a minute, and
// the authorization code must be single-use, which needs server-side state. One
// replica therefore serves at a time, and a rollout fails any login in flight
// with a request the user simply retries. The scale-out path, if it is ever
// needed, is to put the three maps behind a small interface and back it with
// Redis.
type Storage struct {
	config StorageConfig
	client *client

	mutex sync.Mutex
	// requests holds in-flight authorization requests by id.
	requests map[string]*authRequest
	// codes maps an authorization code to a request id. It is dropped
	// together with the request, which is what makes a code single-use.
	codes map[string]string
	// identities holds the claims of completed logins by subject, so that
	// /userinfo can still answer after the request has been exchanged.
	identities map[string]retainedClaims
}

type retainedClaims struct {
	claims    Claims
	expiresAt time.Time
}

// NewStorage validates the registration and builds the storage.
func NewStorage(config StorageConfig) (*Storage, error) {
	if config.Keys == nil {
		return nil, fmt.Errorf("%w: no key material", ErrInvalidClient)
	}

	registered, err := newClient(config.Client, config.AllowInsecureForTests)
	if err != nil {
		return nil, err
	}

	// Fail at startup rather than on the first login: a misconfigured email
	// domain would otherwise surface as Zitadel refusing to create a user,
	// which is a long way from the cause.
	if err := checkDomain(config.SyntheticEmailDomain); err != nil {
		return nil, err
	}

	return &Storage{
		config:     config,
		client:     registered,
		requests:   make(map[string]*authRequest),
		codes:      make(map[string]string),
		identities: make(map[string]retainedClaims),
	}, nil
}

// CreateAuthRequest records an authorization request.
//
// This is where the flow is narrowed to the one we serve. The library is
// deliberately permissive — it accepts an absent code challenge, and an empty
// challenge method which RFC 7636 defaults to plain — so requiring PKCE with
// S256 is our policy and has to be stated here. Note that Zitadel's "Use PKCE"
// flag is off by default, so this gate is also what forces the operator to
// switch it on.
func (s *Storage) CreateAuthRequest(
	_ context.Context,
	request *oidc.AuthRequest,
	_ string,
) (op.AuthRequest, error) {
	if request.ClientID != s.client.GetID() {
		return nil, oidc.ErrInvalidRequest().WithDescription("unknown client")
	}

	if request.ResponseType != oidc.ResponseTypeCode {
		return nil, oidc.ErrInvalidRequest().WithDescription(
			"only the authorization code flow is served")
	}

	if !slices.Contains(request.Scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}

	if request.CodeChallenge == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription(
			"PKCE is required: code_challenge is missing")
	}

	if request.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription(
			"only code_challenge_method=S256 is accepted")
	}

	id, err := randomID()
	if err != nil {
		return nil, err
	}

	recorded := &authRequest{
		id:           id,
		clientID:     request.ClientID,
		redirectURI:  request.RedirectURI,
		scopes:       request.Scopes,
		state:        request.State,
		nonce:        request.Nonce,
		responseType: request.ResponseType,
		responseMode: request.ResponseMode,
		codeChallenge: &oidc.CodeChallenge{
			Challenge: request.CodeChallenge,
			Method:    request.CodeChallengeMethod,
		},
		createdAt: time.Now(),
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.requests[id] = recorded

	return recorded, nil
}

// CompleteAuthRequest records the identity a card attested and marks the
// request authorised. It is the seam the card listener uses: everything up to
// here is protocol, and everything after it is the library's.
func (s *Storage) CompleteAuthRequest(id string, identity domain.CardIdentity) error {
	claims, err := NewClaims(identity, s.config.SyntheticEmailDomain)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	request, present := s.requests[id]
	if !present {
		return fmt.Errorf("%w: %s", ErrUnknownAuthRequest, id)
	}

	request.subject = claims.Sub
	request.acr = claims.ACR
	request.authTime = time.Now()
	request.done = true

	s.identities[claims.Sub] = retainedClaims{
		claims:    claims,
		expiresAt: time.Now().Add(identityLifetime),
	}

	return nil
}

// AuthRequestByID resolves a request the card listener was handed.
func (s *Storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	request, present := s.requests[id]
	if !present {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAuthRequest, id)
	}

	return request, nil
}

// AuthRequestByCode resolves a request during the code exchange.
func (s *Storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id, present := s.codes[code]
	if !present {
		return nil, fmt.Errorf("%w: the code is unknown or already used", ErrUnknownAuthRequest)
	}

	request, present := s.requests[id]
	if !present {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAuthRequest, id)
	}

	return request, nil
}

// SaveAuthCode indexes the authorization code against the request.
func (s *Storage) SaveAuthCode(_ context.Context, id string, code string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, present := s.requests[id]; !present {
		return fmt.Errorf("%w: %s", ErrUnknownAuthRequest, id)
	}

	s.codes[code] = id

	return nil
}

// DeleteAuthRequest removes the request and every code pointing at it.
//
// Dropping the code index is what makes an authorization code single-use. The
// library calls this when it exchanges the code, so a replay finds nothing.
func (s *Storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.requests, id)

	for code, requestID := range s.codes {
		if requestID == id {
			delete(s.codes, code)
		}
	}

	return nil
}

// CreateAccessToken issues an opaque access token. Its only purpose is to let
// Zitadel call /userinfo when it is configured to read claims that way.
func (s *Storage) CreateAccessToken(
	_ context.Context,
	request op.TokenRequest,
) (string, time.Time, error) {
	id, err := randomID()
	if err != nil {
		return "", time.Time{}, err
	}

	// The token carries no claims of its own: /userinfo resolves them from
	// the subject, which the library passes back to SetUserinfoFromToken.
	_ = request

	return id, time.Now().Add(accessTokenLifetime), nil
}

// ForgetExpired drops authorization requests and retained identities that have
// aged out. A request nobody completed must not sit in memory until the process
// restarts.
func (s *Storage) ForgetExpired(now time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for id, request := range s.requests {
		if now.Sub(request.createdAt) < authRequestLifetime {
			continue
		}

		delete(s.requests, id)

		for code, requestID := range s.codes {
			if requestID == id {
				delete(s.codes, code)
			}
		}
	}

	for subject, retained := range s.identities {
		if now.After(retained.expiresAt) {
			delete(s.identities, subject)
		}
	}
}

// GetClientByClientID returns the single registered relying party.
func (s *Storage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	if clientID != s.client.GetID() {
		return nil, fmt.Errorf("%w: unknown client %q", ErrInvalidClient, clientID)
	}

	return s.client, nil
}

// AuthorizeClientIDSecret checks the relying party's credential.
//
// Both halves are compared in constant time over their digests, so that neither
// the secret's length nor a shared prefix leaks through timing.
func (s *Storage) AuthorizeClientIDSecret(_ context.Context, clientID, secret string) error {
	idMatches := constantTimeEqual(clientID, s.client.GetID())
	secretMatches := constantTimeEqual(secret, s.config.Client.Secret)

	if !idMatches || !secretMatches {
		return fmt.Errorf("%w: client authentication failed", ErrInvalidClient)
	}

	return nil
}

// SetUserinfoFromScopes fills the claims for the id_token and /userinfo.
//
// The same function backs both paths deliberately: whether Zitadel reads the
// id_token or calls /userinfo is an administrator's toggle we do not control, so
// the two must never disagree.
func (s *Storage) SetUserinfoFromScopes(
	_ context.Context,
	userinfo *oidc.UserInfo,
	subject string,
	_ string,
	scopes []string,
) error {
	return s.fillUserinfo(userinfo, subject, scopes)
}

// SetUserinfoFromToken backs the /userinfo endpoint.
func (s *Storage) SetUserinfoFromToken(
	_ context.Context,
	userinfo *oidc.UserInfo,
	_ string,
	subject string,
	_ string,
) error {
	return s.fillUserinfo(
		userinfo, subject, []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail})
}

// GetPrivateClaimsFromScopes adds nothing: every claim this provider issues is
// part of the user info, so that it reaches Zitadel whichever way the
// administrator has configured it to read them.
//
// An empty map rather than nil, so that the absence of extra claims is stated
// rather than left to the caller to infer from two nils.
func (s *Storage) GetPrivateClaimsFromScopes(
	context.Context, string, string, []string,
) (map[string]any, error) {
	return map[string]any{}, nil
}

// SigningKey returns the key tokens are signed with.
func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	return s.config.Keys.SigningKey(), nil
}

// SignatureAlgorithms reports what goes into the discovery document's
// id_token_signing_alg_values_supported.
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.config.Keys.SigningKey().SignatureAlgorithm()}, nil
}

// KeySet returns the public keys served at /keys.
//
// The conversion is to op.Key, an interface over the public half only. The keys
// package keeps private and public in separate types precisely so that this
// method cannot hand out private material by mistake.
func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	published := s.config.Keys.PublicKeys()

	set := make([]op.Key, 0, len(published))
	for _, key := range published {
		set = append(set, key)
	}

	return set, nil
}

// Health reports whether the storage can serve. It holds no external
// dependency, so it is healthy as soon as it exists.
func (s *Storage) Health(context.Context) error { return nil }

func (s *Storage) fillUserinfo(
	userinfo *oidc.UserInfo,
	subject string,
	scopes []string,
) error {
	s.mutex.Lock()
	retained, present := s.identities[subject]
	s.mutex.Unlock()

	if !present {
		return fmt.Errorf("%w: no identity for subject", ErrUnknownAuthRequest)
	}

	retained.claims.Apply(userinfo, scopes)

	return nil
}

// randomID produces an unguessable identifier for a request or a token.
func randomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("could not read random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// constantTimeEqual compares two strings without leaking their contents or
// lengths through timing, by comparing fixed-size digests instead.
func constantTimeEqual(a, b string) bool {
	left := sha256.Sum256([]byte(a))
	right := sha256.Sum256([]byte(b))

	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
