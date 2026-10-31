// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package oidcop is the OpenID Provider: it exchanges a card identity for an
// id_token that Zitadel can broker.
//
// The provider itself is github.com/zitadel/oidc, which already implements the
// parts that get an OpenID Provider breached — exact redirect_uri matching,
// single-use authorization codes, PKCE verification, at_hash and c_hash
// computation — and is continuously tested by Zitadel against Zitadel. What
// this package supplies is the storage and the client registration, which are
// almost entirely bookkeeping.
package oidcop

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// ErrInvalidClient wraps a misconfigured relying party registration.
var ErrInvalidClient = errors.New("invalid client registration")

// idTokenLifetime is how long an issued id_token is accepted. It is short
// because the token's only job is to carry the identity to Zitadel, which
// immediately establishes its own session.
const idTokenLifetime = 5 * time.Minute

// ClientConfig registers the one relying party this provider serves: Zitadel.
type ClientConfig struct {
	// ID and Secret are what Zitadel is configured with.
	ID     string
	Secret string
	// RedirectURIs is an exact-match allowlist. Zitadel's callback differs
	// between its login versions, so both may need to be listed.
	RedirectURIs []string
	// LoginURL is the card listener's login endpoint, which the provider
	// redirects the browser to. It lives on a different host from the rest
	// of the provider: only this endpoint sits behind mTLS.
	LoginURL string
}

// client is the single registered relying party.
type client struct {
	config ClientConfig
}

// newClient validates the registration and builds the client.
//
// Every redirect URI must be https. The library permits http for a
// confidential client doing the code flow, so refusing it here is our own
// policy rather than the library's — and it must be refused at startup, where
// it is visible, rather than discovered in production.
func newClient(config ClientConfig, allowInsecure bool) (*client, error) {
	if strings.TrimSpace(config.ID) == "" {
		return nil, fmt.Errorf("%w: no client id", ErrInvalidClient)
	}

	if len(config.Secret) < minimumSecretLength {
		return nil, fmt.Errorf("%w: the client secret is shorter than %d characters",
			ErrInvalidClient, minimumSecretLength)
	}

	if len(config.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: no redirect uri", ErrInvalidClient)
	}

	for _, raw := range config.RedirectURIs {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not a url: %w", ErrInvalidClient, raw, err)
		}

		if !allowInsecure && parsed.Scheme != "https" {
			return nil, fmt.Errorf("%w: the redirect uri %q is not https", ErrInvalidClient, raw)
		}
	}

	parsedLogin, err := url.Parse(config.LoginURL)
	if err != nil || parsedLogin.Host == "" {
		return nil, fmt.Errorf("%w: the login url %q is not a url", ErrInvalidClient, config.LoginURL)
	}

	if !allowInsecure && parsedLogin.Scheme != "https" {
		return nil, fmt.Errorf(
			"%w: the login url %q must be https", ErrInvalidClient, config.LoginURL)
	}

	return &client{config: config}, nil
}

// minimumSecretLength is the floor for the shared secret Zitadel authenticates
// with. 43 characters is 256 bits of base64url entropy.
const minimumSecretLength = 43

func (c *client) GetID() string { return c.config.ID }

// RedirectURIs is an exact-match allowlist. The glob interface the library
// offers is deliberately not implemented: a wrong string must fail closed and
// visibly.
func (c *client) RedirectURIs() []string { return c.config.RedirectURIs }

// PostLogoutRedirectURIs is empty: this provider has no logout flow. A card
// session ends when the browser closes, since browsers cache the selected
// client certificate for the lifetime of the process.
func (c *client) PostLogoutRedirectURIs() []string { return nil }

func (c *client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }

// AuthMethod is client_secret_basic. Zitadel's relying party probes the header
// style first and falls back to the body, and the library accepts either as
// long as Config.AuthMethodPost is set.
func (c *client) AuthMethod() oidc.AuthMethod { return oidc.AuthMethodBasic }

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

// GrantTypes is the authorization code grant alone.
//
// This is load-bearing beyond its appearance: the library decides whether to
// mint a refresh token by checking the client's grant types, so listing only
// the code grant makes the refresh token path unreachable even if a caller
// requests offline_access.
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode}
}

// LoginURL is where the provider sends the browser to have the card read. It
// points at the mTLS listener, which is the only place a client certificate is
// demanded.
func (c *client) LoginURL(id string) string {
	return c.config.LoginURL + "?id=" + url.QueryEscape(id)
}

func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }

func (c *client) IDTokenLifetime() time.Duration { return idTokenLifetime }

// DevMode must stay false. True would let the library accept an http redirect
// uri.
func (c *client) DevMode() bool { return false }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed rejects scopes beyond the standard ones. The provider has
// exactly one relying party and no resource scopes to grant.
func (c *client) IsScopeAllowed(string) bool { return false }

// IDTokenUserinfoClaimsAssertion must be true, and the reason is not obvious.
//
// The code exchange always creates an access token, and when this returns false
// the library strips the profile, email, address and phone scopes from the
// id_token. The token would then carry only sub, and Zitadel's "map ID token to
// user info" mode would find nothing to provision a user from.
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }

// ClockSkew is zero. Tokens live five minutes; tolerating drift on top of that
// would widen the window a stolen token is usable in for no operational gain.
func (c *client) ClockSkew() time.Duration { return 0 }
