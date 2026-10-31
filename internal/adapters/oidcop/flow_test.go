// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package oidcop_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/motrice/smartcard-op/internal/adapters/oidcop"
)

// The flow is driven by zitadel/oidc's own relying party, which is exactly the
// client implementation Zitadel uses. Testing against it rather than against a
// hand-rolled client is what makes the result mean something: the pairing under
// test is the pairing that will run in production.

// provider stands up the issuer listener and the card listener on httptest
// servers and returns the storage, the relying party and the card login URL.
type provider struct {
	storage      *oidcop.Storage
	relyingParty rp.RelyingParty
	cardLogin    string
	issuer       string
}

func newProvider(t *testing.T) *provider {
	t.Helper()

	// The issuer URL has to be known before the provider is built, and the
	// provider has to exist before the server can serve it, so the listener
	// is created first and its handler filled in afterwards.
	issuerMux := http.NewServeMux()
	issuerServer := httptest.NewServer(issuerMux)
	t.Cleanup(issuerServer.Close)

	cardMux := http.NewServeMux()
	cardServer := httptest.NewServer(cardMux)
	t.Cleanup(cardServer.Close)

	relyingPartyServer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(relyingPartyServer.Close)

	redirectURI := relyingPartyServer.URL + "/idps/callback"
	cardLogin := cardServer.URL + "/login"

	store, err := oidcop.NewStorage(oidcop.StorageConfig{
		Keys: keySet(t),
		Client: oidcop.ClientConfig{
			ID:           testClientID,
			Secret:       testSecret,
			RedirectURIs: []string{redirectURI},
			LoginURL:     cardLogin,
		},
		SyntheticEmailDomain:  "card-noreply.example.se",
		AllowInsecureForTests: true,
	})
	if err != nil {
		t.Fatalf("NewStorage returned error: %v", err)
	}

	config := oidcop.ProviderConfig{
		Issuer:                issuerServer.URL,
		CryptoKeyID:           "k1",
		AllowInsecureForTests: true,
	}
	copy(config.CryptoKey[:], strings.Repeat("k", 32))

	openIDProvider, err := oidcop.NewProvider(store, config)
	if err != nil {
		t.Fatalf("NewProvider returned error: %v", err)
	}

	issuerMux.Handle("/", openIDProvider)

	// The card listener serves only /login. The OIDC endpoints are not
	// registered here at all, which is the point: a misrouted request
	// cannot reach them without a certificate.
	callback := oidcop.CallbackURL(openIDProvider)

	login, err := oidcop.LoginHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")

			if err := store.CompleteAuthRequest(id, cardIdentity(t)); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)

				return
			}

			http.Redirect(w, r, callback(r.Context(), id), http.StatusFound)
		}), config)
	if err != nil {
		t.Fatalf("LoginHandler returned error: %v", err)
	}

	cardMux.Handle("/login", login)

	party, err := rp.NewRelyingPartyOIDC(
		context.Background(),
		issuerServer.URL,
		testClientID,
		testSecret,
		redirectURI,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		rp.WithPKCE(nil),
	)
	if err != nil {
		t.Fatalf("NewRelyingPartyOIDC returned error: %v", err)
	}

	return &provider{
		storage:      store,
		relyingParty: party,
		cardLogin:    cardLogin,
		issuer:       issuerServer.URL,
	}
}

// Discovery is the first thing Zitadel does, when its identity provider object
// is constructed. That NewRelyingPartyOIDC succeeded already proves the
// document is well formed; this asserts what it advertises.
func TestDiscoveryAdvertisesOnlyWhatWeServe(t *testing.T) {
	t.Parallel()

	harness := newProvider(t)

	discovered, err := client.Discover(
		context.Background(), harness.issuer, http.DefaultClient)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	if !slices.Contains(discovered.CodeChallengeMethodsSupported, oidc.CodeChallengeMethodS256) {
		t.Errorf("code_challenge_methods_supported = %v, want S256",
			discovered.CodeChallengeMethodsSupported)
	}

	for _, grant := range discovered.GrantTypesSupported {
		if grant == oidc.GrantTypeRefreshToken {
			t.Error("the refresh token grant is advertised but not served")
		}
	}

	if len(discovered.IDTokenSigningAlgValuesSupported) != 1 ||
		discovered.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256]",
			discovered.IDTokenSigningAlgValuesSupported)
	}
}

// The whole flow: authorize, read the card, exchange the code, verify the
// id_token. If this passes, Zitadel can federate to the provider.
func TestTheFlowIssuesAVerifiableIDToken(t *testing.T) {
	t.Parallel()

	harness := newProvider(t)

	// A browser that follows redirects but stops before the relying party's
	// callback, so that the code and state can be read off the location.
	var authorizationCode string

	browser := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if code := req.URL.Query().Get("code"); code != "" {
				authorizationCode = code

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	authURL := rp.AuthURL("state-1", harness.relyingParty,
		rp.WithCodeChallenge(oidc.NewSHACodeChallenge("a-verifier-of-sufficient-length-1234")))

	response, err := fetch(t, browser, authURL)
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if authorizationCode == "" {
		t.Fatalf("no authorization code was issued; the browser ended at %s with %s",
			response.Request.URL, response.Status)
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](
		context.Background(), authorizationCode, harness.relyingParty,
		rp.WithCodeVerifier("a-verifier-of-sufficient-length-1234"))
	if err != nil {
		t.Fatalf("the code exchange failed: %v", err)
	}

	claims := tokens.IDTokenClaims
	if claims.Subject != "195606019577" {
		t.Errorf("sub = %q", claims.Subject)
	}

	// The id_token must carry the profile and email claims, not only sub.
	// That depends on the client asserting user info claims into the token;
	// without it Zitadel's id-token mapping mode would find nothing to
	// provision a user from.
	mandatory := map[string]string{
		"preferred_username": claims.PreferredUsername,
		"name":               claims.Name,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
		"email":              claims.Email,
	}
	for field, value := range mandatory {
		if value == "" {
			t.Errorf("the id_token's %s is empty; Zitadel refuses to create the user", field)
		}
	}

	if acr := claims.AuthenticationContextClassReference; acr !=
		"http://id.elegnamnden.se/loa/1.0/loa3" {
		t.Errorf("acr = %q", acr)
	}

	amr := strings.Join(claims.AuthenticationMethodsReferences, " ")
	for _, want := range []string{"sc", "pin", "hwk", "mfa"} {
		if !strings.Contains(amr, want) {
			t.Errorf("amr = %v, lacks %q",
				claims.AuthenticationMethodsReferences, want)
		}
	}

	if personalNumber := claims.Claims[oidcop.ClaimPersonalIdentityNumber]; personalNumber != "195606019577" {
		t.Errorf("the Swedish identity number claim = %v", personalNumber)
	}

	// The same claims must be available from /userinfo, since whether
	// Zitadel reads the token or calls the endpoint is an administrator's
	// toggle.
	info, err := rp.Userinfo[*oidc.UserInfo](
		context.Background(), tokens.AccessToken, tokens.TokenType,
		claims.Subject, harness.relyingParty)
	if err != nil {
		t.Fatalf("Userinfo returned error: %v", err)
	}

	if info.GivenName != claims.GivenName || info.Email != claims.Email {
		t.Errorf("userinfo disagrees with the id_token: %+v", info)
	}
}

// An authorization code must work exactly once. A replay is the classic attack
// against the code flow, and the library's single-use guarantee depends on our
// storage dropping the code index together with the request.
func TestAReplayedCodeIsRejected(t *testing.T) {
	t.Parallel()

	harness := newProvider(t)

	var authorizationCode string

	browser := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if code := req.URL.Query().Get("code"); code != "" {
				authorizationCode = code

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	const verifier = "a-verifier-of-sufficient-length-1234"

	response, err := fetch(t, browser, rp.AuthURL("state-1", harness.relyingParty,
		rp.WithCodeChallenge(oidc.NewSHACodeChallenge(verifier))))
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if authorizationCode == "" {
		t.Fatal("no authorization code was issued")
	}

	if _, err := rp.CodeExchange[*oidc.IDTokenClaims](
		context.Background(), authorizationCode, harness.relyingParty,
		rp.WithCodeVerifier(verifier)); err != nil {
		t.Fatalf("the first code exchange failed: %v", err)
	}

	if _, err := rp.CodeExchange[*oidc.IDTokenClaims](
		context.Background(), authorizationCode, harness.relyingParty,
		rp.WithCodeVerifier(verifier)); err == nil {
		t.Error("the authorization code was accepted twice")
	}
}

// A wrong code verifier must be refused. PKCE is the whole protection against
// an intercepted authorization code, so this is the test that proves it is
// actually being verified rather than merely required.
func TestAWrongCodeVerifierIsRejected(t *testing.T) {
	t.Parallel()

	harness := newProvider(t)

	var authorizationCode string

	browser := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if code := req.URL.Query().Get("code"); code != "" {
				authorizationCode = code

				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	response, err := fetch(t, browser, rp.AuthURL("state-1", harness.relyingParty,
		rp.WithCodeChallenge(
			oidc.NewSHACodeChallenge("the-real-verifier-of-good-length-01"))))
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if authorizationCode == "" {
		t.Fatal("no authorization code was issued")
	}

	if _, err := rp.CodeExchange[*oidc.IDTokenClaims](
		context.Background(), authorizationCode, harness.relyingParty,
		rp.WithCodeVerifier("a-different-verifier-of-good-length")); err == nil {
		t.Error("a wrong code verifier was accepted")
	}
}

// Visiting the login endpoint for an unknown request must not mint anything.
// In production this is what a stale bookmark or an expired dialog looks like.
func TestLoginForAnUnknownRequestIssuesNothing(t *testing.T) {
	t.Parallel()

	harness := newProvider(t)

	response, err := fetch(t, http.DefaultClient,
		harness.cardLogin+"?id="+url.QueryEscape("no-such-request"))
	if err != nil {
		t.Fatalf("the login request failed: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusForbidden {
		t.Errorf("status = %s, want 403", response.Status)
	}
}

// fetch performs a GET with a context, which is what a well-behaved client
// does and what the linter insists on.
func fetch(t *testing.T, client *http.Client, address string) (*http.Response, error) {
	t.Helper()

	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}

	return client.Do(request)
}
