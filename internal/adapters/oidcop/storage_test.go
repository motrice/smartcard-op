// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/motrice/smartcard-op/internal/adapters/keys"
	"github.com/motrice/smartcard-op/internal/adapters/oidcop"
	"github.com/motrice/smartcard-op/internal/domain"
)

// The storage must satisfy the library's interfaces. Asserting it at compile
// time turns an upstream interface change into a build failure rather than a
// runtime panic on a login nobody is watching.
var _ op.Storage = (*oidcop.Storage)(nil)

const (
	testClientID = "zitadel"
	testSecret   = "0123456789012345678901234567890123456789012"
	testRedirect = "https://id.example.se/idps/callback"
	testLoginURL = "https://card.idp.example.se/login"
)

func keySet(t *testing.T) *keys.Set {
	t.Helper()

	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "current.pem"), block, 0o600); err != nil {
		t.Fatalf("could not write key: %v", err)
	}

	set, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("keys.Load returned error: %v", err)
	}

	return set
}

func storage(t *testing.T) *oidcop.Storage {
	t.Helper()

	store, err := oidcop.NewStorage(oidcop.StorageConfig{
		Keys: keySet(t),
		Client: oidcop.ClientConfig{
			ID:           testClientID,
			Secret:       testSecret,
			RedirectURIs: []string{testRedirect},
			LoginURL:     testLoginURL,
		},
		SyntheticEmailDomain: "card-noreply.example.se",
	})
	if err != nil {
		t.Fatalf("NewStorage returned error: %v", err)
	}

	return store
}

func authRequest() *oidc.AuthRequest {
	return &oidc.AuthRequest{
		Scopes:              oidc.SpaceDelimitedArray{oidc.ScopeOpenID, oidc.ScopeProfile},
		ResponseType:        oidc.ResponseTypeCode,
		ClientID:            testClientID,
		RedirectURI:         testRedirect,
		State:               "state-1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}
}

// PKCE is required, and that is our policy rather than the library's: it
// permits an absent challenge, and an empty method which RFC 7636 defaults to
// plain. Zitadel's "Use PKCE" flag is off by default, so this gate is also what
// forces the operator to switch it on.
func TestCreateAuthRequestRequiresPKCEWithS256(t *testing.T) {
	t.Parallel()

	t.Run("S256 is accepted", func(t *testing.T) {
		t.Parallel()

		request, err := storage(t).CreateAuthRequest(
			context.Background(), authRequest(), "")
		if err != nil {
			t.Fatalf("CreateAuthRequest returned error: %v", err)
		}

		if request.GetID() == "" {
			t.Error("the auth request has no id")
		}

		if request.Done() {
			t.Error("a fresh auth request is already done")
		}
	})

	cases := map[string]func(*oidc.AuthRequest){
		"no challenge":   func(r *oidc.AuthRequest) { r.CodeChallenge = "" },
		"empty method":   func(r *oidc.AuthRequest) { r.CodeChallengeMethod = "" },
		"plain method":   func(r *oidc.AuthRequest) { r.CodeChallengeMethod = oidc.CodeChallengeMethodPlain },
		"unknown method": func(r *oidc.AuthRequest) { r.CodeChallengeMethod = "S512" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := authRequest()
			mutate(request)

			_, err := storage(t).CreateAuthRequest(context.Background(), request, "")
			if err == nil {
				t.Fatal("CreateAuthRequest returned no error, want one")
			}
		})
	}
}

func TestCreateAuthRequestRejectsFlowsWeDoNotServe(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*oidc.AuthRequest){
		"implicit flow": func(r *oidc.AuthRequest) { r.ResponseType = oidc.ResponseTypeIDToken },
		"no openid scope": func(r *oidc.AuthRequest) {
			r.Scopes = oidc.SpaceDelimitedArray{oidc.ScopeProfile}
		},
		"another client": func(r *oidc.AuthRequest) { r.ClientID = "someone-else" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := authRequest()
			mutate(request)

			_, err := storage(t).CreateAuthRequest(context.Background(), request, "")
			if err == nil {
				t.Fatal("CreateAuthRequest returned no error, want one")
			}
		})
	}
}

// An authorization code must be usable exactly once. The library deletes the
// auth request when it exchanges the code, so the code index has to go with it
// — otherwise a replayed code would resolve to a request that no longer exists
// and the failure mode would depend on map ordering rather than on policy.
func TestDeleteAuthRequestDropsTheCodeIndex(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	request, err := store.CreateAuthRequest(ctx, authRequest(), "")
	if err != nil {
		t.Fatalf("CreateAuthRequest returned error: %v", err)
	}

	const code = "the-code"

	if err := store.SaveAuthCode(ctx, request.GetID(), code); err != nil {
		t.Fatalf("SaveAuthCode returned error: %v", err)
	}

	if _, err := store.AuthRequestByCode(ctx, code); err != nil {
		t.Fatalf("AuthRequestByCode returned error: %v", err)
	}

	if err := store.DeleteAuthRequest(ctx, request.GetID()); err != nil {
		t.Fatalf("DeleteAuthRequest returned error: %v", err)
	}

	if _, err := store.AuthRequestByCode(ctx, code); err == nil {
		t.Error("the code still resolves after the auth request was deleted")
	}

	if _, err := store.AuthRequestByID(ctx, request.GetID()); err == nil {
		t.Error("the auth request still resolves after deletion")
	}
}

func TestAuthorizeClientIDSecret(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	if err := store.AuthorizeClientIDSecret(ctx, testClientID, testSecret); err != nil {
		t.Fatalf("the correct secret was rejected: %v", err)
	}

	cases := map[string][2]string{
		"wrong secret": {testClientID, strings.Repeat("x", len(testSecret))},
		"empty secret": {testClientID, ""},
		"wrong client": {"someone-else", testSecret},
		"secret as id": {testSecret, testSecret},
	}

	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := store.AuthorizeClientIDSecret(ctx, pair[0], pair[1]); err == nil {
				t.Error("an incorrect credential was accepted")
			}
		})
	}
}

// Completing an auth request is the seam the card listener uses: it hands over
// the identity the certificate attested, and the library takes over from there.
func TestCompleteAuthRequestCarriesTheIdentityIntoUserinfo(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	request, err := store.CreateAuthRequest(ctx, authRequest(), "")
	if err != nil {
		t.Fatalf("CreateAuthRequest returned error: %v", err)
	}

	if err := store.CompleteAuthRequest(request.GetID(), cardIdentity(t)); err != nil {
		t.Fatalf("CompleteAuthRequest returned error: %v", err)
	}

	completed, err := store.AuthRequestByID(ctx, request.GetID())
	if err != nil {
		t.Fatalf("AuthRequestByID returned error: %v", err)
	}

	if !completed.Done() {
		t.Error("the auth request is not done after completion")
	}

	if got := completed.GetSubject(); got != "195606019577" {
		t.Errorf("GetSubject() = %q", got)
	}

	if got := completed.GetACR(); got != "http://id.elegnamnden.se/loa/1.0/loa3" {
		t.Errorf("GetACR() = %q", got)
	}

	// RFC 8176: a smartcard login is proof of possession of a hardware key
	// plus a PIN, which is more than one factor.
	amr := strings.Join(completed.GetAMR(), " ")
	for _, want := range []string{"sc", "pin", "hwk", "mfa"} {
		if !strings.Contains(amr, want) {
			t.Errorf("GetAMR() = %v, lacks %q", completed.GetAMR(), want)
		}
	}

	userinfo := new(oidc.UserInfo)
	if err := store.SetUserinfoFromScopes(
		ctx, userinfo, completed.GetSubject(), testClientID,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}); err != nil {
		t.Fatalf("SetUserinfoFromScopes returned error: %v", err)
	}

	mandatory := map[string]string{
		"sub":                userinfo.Subject,
		"preferred_username": userinfo.PreferredUsername,
		"name":               userinfo.Name,
		"given_name":         userinfo.GivenName,
		"family_name":        userinfo.FamilyName,
		"email":              userinfo.Email,
	}
	for field, value := range mandatory {
		if value == "" {
			t.Errorf("%s is empty; Zitadel refuses to create the user", field)
		}
	}

	if !bool(userinfo.EmailVerified) {
		t.Error("email_verified is false; Zitadel would mail a code to an undeliverable address")
	}

	claims := userinfo.Claims
	if claims[oidcop.ClaimPersonalIdentityNumber] != "195606019577" {
		t.Errorf("the Swedish identity number claim = %v",
			claims[oidcop.ClaimPersonalIdentityNumber])
	}
}

// Both userinfo paths must yield the same claims, because whether Zitadel reads
// the id_token or calls /userinfo is an administrator's toggle we do not
// control.
func TestUserinfoFromTokenMatchesUserinfoFromScopes(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	request, err := store.CreateAuthRequest(ctx, authRequest(), "")
	if err != nil {
		t.Fatalf("CreateAuthRequest returned error: %v", err)
	}

	if err := store.CompleteAuthRequest(request.GetID(), cardIdentity(t)); err != nil {
		t.Fatalf("CompleteAuthRequest returned error: %v", err)
	}

	fromScopes := new(oidc.UserInfo)
	if err := store.SetUserinfoFromScopes(ctx, fromScopes, "195606019577", testClientID,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}); err != nil {
		t.Fatalf("SetUserinfoFromScopes returned error: %v", err)
	}

	fromToken := new(oidc.UserInfo)
	if err := store.SetUserinfoFromToken(
		ctx, fromToken, "any-token", "195606019577", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken returned error: %v", err)
	}

	if fromToken.Subject != fromScopes.Subject ||
		fromToken.GivenName != fromScopes.GivenName ||
		fromToken.Email != fromScopes.Email {
		t.Errorf("the two userinfo paths disagree:\n  scopes: %+v\n  token:  %+v",
			fromScopes, fromToken)
	}
}

func TestCompleteAuthRequestRejectsAnUnknownRequest(t *testing.T) {
	t.Parallel()

	err := storage(t).CompleteAuthRequest("no-such-request", cardIdentity(t))
	if !errors.Is(err, oidcop.ErrUnknownAuthRequest) {
		t.Fatalf("error = %v, want ErrUnknownAuthRequest", err)
	}
}

// Everything the provider does not serve must fail loudly. An auditor reads one
// file and sees at a glance that refresh tokens, device flow, introspection and
// JWT profile are all off.
func TestUnsupportedFeaturesAllFail(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	if _, _, _, err := store.CreateAccessAndRefreshTokens(ctx, nil, ""); err == nil {
		t.Error("CreateAccessAndRefreshTokens did not fail")
	}

	if _, err := store.TokenRequestByRefreshToken(ctx, "token"); err == nil {
		t.Error("TokenRequestByRefreshToken did not fail")
	}

	if _, _, err := store.GetRefreshTokenInfo(ctx, testClientID, "token"); err == nil {
		t.Error("GetRefreshTokenInfo did not fail")
	}

	if err := store.RevokeToken(ctx, "token", "subject", testClientID); err == nil {
		t.Error("RevokeToken did not fail")
	}

	if err := store.SetIntrospectionFromToken(
		ctx, new(oidc.IntrospectionResponse), "token", "subject", testClientID); err == nil {
		t.Error("SetIntrospectionFromToken did not fail")
	}

	if _, err := store.GetKeyByIDAndClientID(ctx, "kid", testClientID); err == nil {
		t.Error("GetKeyByIDAndClientID did not fail")
	}

	if _, err := store.ValidateJWTProfileScopes(ctx, "subject", nil); err == nil {
		t.Error("ValidateJWTProfileScopes did not fail")
	}
}

func TestStorageServesTheKeySet(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	algorithms, err := store.SignatureAlgorithms(ctx)
	if err != nil {
		t.Fatalf("SignatureAlgorithms returned error: %v", err)
	}

	if len(algorithms) != 1 || algorithms[0] != "RS256" {
		t.Errorf("SignatureAlgorithms() = %v, want [RS256]", algorithms)
	}

	signing, err := store.SigningKey(ctx)
	if err != nil {
		t.Fatalf("SigningKey returned error: %v", err)
	}

	if signing.ID() == "" {
		t.Error("the signing key has no id")
	}

	published, err := store.KeySet(ctx)
	if err != nil {
		t.Fatalf("KeySet returned error: %v", err)
	}

	if len(published) != 1 {
		t.Fatalf("%d published keys, want 1", len(published))
	}

	// The key set must never carry private material. keys.PublicKey cannot,
	// by construction, but the storage could still hand out the wrong type.
	if _, isPrivate := published[0].Key().(*rsa.PrivateKey); isPrivate {
		t.Fatal("the key set publishes a private key")
	}

	if _, isPublic := published[0].Key().(*rsa.PublicKey); !isPublic {
		t.Errorf("the key set publishes a %T", published[0].Key())
	}
}

func TestNewStorageValidatesTheClientRegistration(t *testing.T) {
	t.Parallel()

	cases := map[string]oidcop.ClientConfig{
		"no client id": {
			Secret: testSecret, RedirectURIs: []string{testRedirect}, LoginURL: testLoginURL,
		},
		"short secret": {
			ID: testClientID, Secret: "short",
			RedirectURIs: []string{testRedirect}, LoginURL: testLoginURL,
		},
		"no redirect uri": {
			ID: testClientID, Secret: testSecret, LoginURL: testLoginURL,
		},
		"plaintext redirect uri": {
			ID: testClientID, Secret: testSecret,
			RedirectURIs: []string{"http://id.example.se/idps/callback"},
			LoginURL:     testLoginURL,
		},
		"plaintext login url": {
			ID: testClientID, Secret: testSecret,
			RedirectURIs: []string{testRedirect},
			LoginURL:     "http://card.idp.example.se/login",
		},
	}

	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcop.NewStorage(oidcop.StorageConfig{
				Keys:                 keySet(t),
				Client:               config,
				SyntheticEmailDomain: "card-noreply.example.se",
			})
			if !errors.Is(err, oidcop.ErrInvalidClient) {
				t.Errorf("error = %v, want ErrInvalidClient", err)
			}
		})
	}
}

// An auth request is short-lived. One that is never completed must not sit in
// memory until the process restarts.
func TestExpiredAuthRequestsAreForgotten(t *testing.T) {
	t.Parallel()

	store := storage(t)
	ctx := context.Background()

	request, err := store.CreateAuthRequest(ctx, authRequest(), "")
	if err != nil {
		t.Fatalf("CreateAuthRequest returned error: %v", err)
	}

	store.ForgetExpired(time.Now().Add(24 * time.Hour))

	if _, err := store.AuthRequestByID(ctx, request.GetID()); err == nil {
		t.Error("an expired auth request still resolves")
	}
}

// cardIdentity builds the identity a successful card read would yield.
func cardIdentity(t *testing.T) domain.CardIdentity {
	t.Helper()

	identity, err := domain.NewCardIdentity(details(), domain.AssuranceLevel3, now)
	if err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}

	return identity
}
