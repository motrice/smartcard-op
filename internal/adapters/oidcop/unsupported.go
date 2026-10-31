// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop

import (
	"context"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Everything this provider does not serve lives in this one file, each method
// naming the feature it disables. An auditor reads seventy lines and sees at a
// glance that refresh tokens, token revocation, introspection, the JWT profile
// and session termination are all off.
//
// The library registers routes for several of these unconditionally, so the
// methods must exist. They fail rather than returning an empty success, because
// an endpoint that answers politely without doing anything is worse than one
// that says it is closed.

// CreateAccessAndRefreshTokens is unreachable: the client registers only the
// authorization code grant, and the library decides whether to mint a refresh
// token by consulting the client's grant types. The method exists so that if
// that ever changes, it fails here rather than silently issuing a long-lived
// credential to a card login.
func (s *Storage) CreateAccessAndRefreshTokens(
	context.Context, op.TokenRequest, string,
) (string, string, time.Time, error) {
	return "", "", time.Time{}, errUnsupported("refresh tokens")
}

// TokenRequestByRefreshToken disables the refresh token grant. A card login is
// re-done by reading the card again, which is the point of a card.
func (s *Storage) TokenRequestByRefreshToken(
	context.Context, string,
) (op.RefreshTokenRequest, error) {
	return nil, errUnsupported("refresh tokens")
}

// GetRefreshTokenInfo disables refresh token introspection.
func (s *Storage) GetRefreshTokenInfo(
	context.Context, string, string,
) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}

// RevokeToken disables the revocation endpoint. Tokens live five minutes and
// are not revocable; the credential that matters is the card, and that is
// revoked through EFOS.
func (s *Storage) RevokeToken(
	context.Context, string, string, string,
) *oidc.Error {
	return oidc.ErrServerError().WithDescription("token revocation is not supported")
}

// TerminateSession disables end_session. The provider holds no session: the
// browser's cached client certificate is what a card user would need to clear,
// and no protocol endpoint can do that.
func (s *Storage) TerminateSession(context.Context, string, string) error {
	return errUnsupported("session termination")
}

// SetIntrospectionFromToken disables the introspection endpoint. Zitadel reads
// the id_token or /userinfo; nothing needs to introspect our access tokens.
func (s *Storage) SetIntrospectionFromToken(
	context.Context, *oidc.IntrospectionResponse, string, string, string,
) error {
	return errUnsupported("token introspection")
}

// GetKeyByIDAndClientID disables private_key_jwt client authentication. The
// relying party authenticates with a shared secret.
func (s *Storage) GetKeyByIDAndClientID(
	context.Context, string, string,
) (*jose.JSONWebKey, error) {
	return nil, errUnsupported("private_key_jwt client authentication")
}

// ValidateJWTProfileScopes disables the JWT profile grant.
func (s *Storage) ValidateJWTProfileScopes(
	context.Context, string, []string,
) ([]string, error) {
	return nil, errUnsupported("the JWT profile grant")
}
