// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

// ProviderConfig is what the OpenID Provider needs beyond its storage.
type ProviderConfig struct {
	// Issuer is the provider's public base URL. It appears in every token
	// and is fetched by Zitadel for discovery, so treat it as immutable
	// after go-live: Zitadel performs discovery when its identity provider
	// object is constructed, and changing the issuer means re-saving the
	// provider there.
	Issuer string
	// CryptoKey encrypts the opaque access tokens. Thirty-two bytes from
	// the same secret the signing keys come from.
	CryptoKey [32]byte
	// CryptoKeyID names the key in case it is ever rotated.
	CryptoKeyID string
	// AllowInsecureForTests permits a plaintext issuer so that an
	// in-process test can drive the flow. Never set it in a deployment.
	AllowInsecureForTests bool
}

// NewProvider assembles the OpenID Provider around the storage.
//
// Everything this provider does not serve is switched off here rather than
// merely left unimplemented: refresh tokens, private_key_jwt, request objects
// and back-channel logout. The library still registers routes for some of them,
// and the storage's disabled methods make those routes fail — but stating it in
// the configuration is also what keeps the discovery document honest about what
// a relying party may attempt.
func NewProvider(storage *Storage, config ProviderConfig) (*op.Provider, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("%w: no issuer", ErrInvalidClient)
	}

	opConfig := &op.Config{
		CryptoKey:   config.CryptoKey,
		CryptoKeyId: config.CryptoKeyID,

		// S256 is the only code challenge method advertised, matching
		// what the storage enforces.
		CodeMethodS256: true,
		// Zitadel's relying party probes client_secret_basic first and
		// falls back to the body, so both must be accepted.
		AuthMethodPost: true,

		AuthMethodPrivateKeyJWT:           false,
		GrantTypeRefreshToken:             false,
		RequestObjectSupported:            false,
		BackChannelLogoutSupported:        false,
		BackChannelLogoutSessionSupported: false,

		SupportedUILocales: []language.Tag{language.Swedish, language.English},
		SupportedScopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
		},
		SupportedClaims: []string{
			"sub",
			"preferred_username",
			"name",
			"given_name",
			"family_name",
			"email",
			"email_verified",
			"locale",
			"acr",
			"amr",
			ClaimPersonalIdentityNumber,
			ClaimOrgAffiliation,
			ClaimEfosID,
			ClaimOrganization,
		},
	}

	options := []op.Option{}
	if config.AllowInsecureForTests {
		options = append(options, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(
		opConfig, storage, op.StaticIssuer(config.Issuer), options...)
	if err != nil {
		return nil, fmt.Errorf("could not build the openid provider: %w", err)
	}

	return provider, nil
}

// LoginHandler wraps the card listener's handler so that it can build the
// provider's callback URL.
//
// The library's AuthCallbackURL reads the issuer from the request context, and
// that context is populated by the provider's own router middleware. The login
// endpoint lives on a different mux on a different host — it is the only thing
// behind mTLS — so the issuer has to be injected here, or the callback redirect
// would be built against an empty issuer.
func LoginHandler(
	handler http.Handler,
	config ProviderConfig,
) (http.Handler, error) {
	issuerFromRequest, err := op.StaticIssuer(config.Issuer)(config.AllowInsecureForTests)
	if err != nil {
		return nil, fmt.Errorf("could not build the issuer interceptor: %w", err)
	}

	return op.NewIssuerInterceptor(issuerFromRequest).Handler(handler), nil
}

// CallbackURL builds the URL the card listener redirects back to once a card
// has been read.
//
// The context must carry the issuer, which is what LoginHandler puts there.
func CallbackURL(provider *op.Provider) func(context.Context, string) string {
	return op.AuthCallbackURL(provider)
}
