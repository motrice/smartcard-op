// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Command smartcard-op is an OpenID Provider that exchanges a verified EFOS
// smartcard for an id_token, which Zitadel brokers as a Generic OIDC Identity
// Provider.
//
// It serves two listeners on two hostnames, and the split is not a deployment
// preference but a requirement. Zitadel fetches the discovery document and the
// JWKS, and performs the code exchange, from its own server — which holds no
// card. Putting the whole provider behind mTLS would break the flow at the
// token exchange. Only GET /login demands a certificate, and the OIDC endpoints
// are not registered on that listener at all, so a misrouted request cannot
// reach them without one.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/audit"
	"github.com/motrice/smartcard-op/internal/adapters/efospki"
	"github.com/motrice/smartcard-op/internal/adapters/keys"
	"github.com/motrice/smartcard-op/internal/adapters/oidcop"
	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/app"
)

// Build metadata, set by the linker.
var (
	version = "dev"
	commit  = "none"
)

const (
	// shutdownGrace is how long in-flight requests are given on a signal. A
	// login takes seconds, so this is generous.
	shutdownGrace = 15 * time.Second
	// janitorInterval is how often expired authorization requests are
	// dropped.
	janitorInterval = time.Minute
	// readHeaderTimeout bounds a slow-header attack. The card listener's
	// headers carry a certificate, so they are larger than usual but not
	// slower to arrive.
	readHeaderTimeout = 10 * time.Second
	// maxHeaderBytes has to accommodate a percent-encoded certificate in
	// the XFCC header.
	maxHeaderBytes = 64 << 10
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(logger); err != nil {
		logger.Error("smartcard-op could not start", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	configuration, err := loadConfig(environment)
	if err != nil {
		return err
	}

	// The audit trail goes to stdout and the application log to stderr, so
	// that retention and access can differ: the audit stream holds personal
	// data and is kept for years, the application log does not and is not.
	auditLog, err := audit.New(os.Stdout, audit.Config{
		Redaction:  configuration.AuditRedaction,
		HMACKey:    configuration.AuditHMACKey,
		Identifier: configuration.InstanceID,
	})
	if err != nil {
		return err
	}

	keySet, err := keys.Load(configuration.KeyDir)
	if err != nil {
		return err
	}

	bundle, err := os.ReadFile(configuration.CABundle)
	if err != nil {
		return fmt.Errorf("could not read the EFOS CA bundle: %w", err)
	}

	trustAnchor, err := efospki.NewTrustAnchor(bundle)
	if err != nil {
		return err
	}

	authenticator := app.NewAuthenticator(app.Dependencies{
		TrustAnchor:       trustAnchor,
		CertificateReader: efospki.NewReader(),
		RevocationChecker: revocation.NewChecker(
			revocation.NewOCSP(nil),
			revocation.NewCRL(nil, configuration.CRLMaxStaleness),
		),
		AuditLog:              auditWriter{log: auditLog},
		Clock:                 systemClock{},
		MinimumAssuranceLevel: configuration.MinimumAssuranceLevel,
	})

	storage, err := oidcop.NewStorage(oidcop.StorageConfig{
		Keys: keySet,
		Client: oidcop.ClientConfig{
			ID:           configuration.ClientID,
			Secret:       configuration.ClientSecret,
			RedirectURIs: configuration.RedirectURIs,
			LoginURL:     configuration.CardLoginURL,
		},
		SyntheticEmailDomain: configuration.SyntheticEmailDomain,
	})
	if err != nil {
		return err
	}

	providerConfig := oidcop.ProviderConfig{
		Issuer:      configuration.Issuer,
		CryptoKey:   configuration.TokenCryptoKey,
		CryptoKeyID: "k1",
	}

	provider, err := oidcop.NewProvider(storage, providerConfig)
	if err != nil {
		return err
	}

	login, err := oidcop.LoginHandler(&cardLogin{
		authenticate: authenticator.Authenticate,
		complete:     storage.CompleteAuthRequest,
		callback:     oidcop.CallbackURL(provider),
		logger:       logger,
	}, providerConfig)
	if err != nil {
		return err
	}

	contents := trustAnchor.Contents()
	logger.Info("smartcard-op starting",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("issuer", configuration.Issuer),
		slog.String("issuer_listen", configuration.IssuerListen),
		slog.String("card_listen", configuration.CardListen),
		slog.String("minimum_assurance_level",
			assuranceLevelText(configuration.MinimumAssuranceLevel)),
		slog.Any("trusted_roots", contents.Roots),
		slog.Any("trusted_issuers", contents.Intermediates),
		slog.String("signing_key_id", keySet.SigningKey().ID()),
		slog.Int("published_keys", len(keySet.PublicKeys())),
		slog.String("audit_redaction", string(configuration.AuditRedaction)),
		slog.String("audit_genesis", auditLog.Genesis()),
		slog.Duration("crl_max_staleness", configuration.CRLMaxStaleness),
	)

	return serve(logger, configuration, provider, login, storage)
}

// serve runs both listeners until a signal arrives.
func serve(
	logger *slog.Logger,
	configuration *config,
	provider http.Handler,
	login http.Handler,
	storage *oidcop.Storage,
) error {
	// The issuer listener serves the whole OIDC router and demands no
	// certificate.
	issuerMux := http.NewServeMux()
	issuerMux.Handle("/", provider)

	// The card listener serves only the login endpoint. Nothing else is
	// registered, so nothing else can be reached through it.
	cardMux := http.NewServeMux()
	cardMux.Handle("GET /login", login)

	issuerServer := newServer(configuration.IssuerListen, issuerMux)
	cardServer := newServer(configuration.CardListen, cardMux)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	failed := make(chan error, 2)

	for name, server := range map[string]*http.Server{
		"issuer": issuerServer,
		"card":   cardServer,
	} {
		go func(name string, server *http.Server) {
			logger.Info("listening", slog.String("listener", name),
				slog.String("address", server.Addr))

			if err := server.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("the %s listener failed: %w", name, err)
			}
		}(name, server)
	}

	// Authorization requests that nobody completed must not accumulate.
	go func() {
		ticker := time.NewTicker(janitorInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				storage.ForgetExpired(now)
			}
		}
	}()

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	var problems []error

	for _, server := range []*http.Server{issuerServer, cardServer} {
		if err := server.Shutdown(shutdownCtx); err != nil {
			problems = append(problems, err)
		}
	}

	return errors.Join(problems...)
}

// newServer applies the timeouts and limits every listener needs. Go's defaults
// are unbounded, which is a slow-loris invitation on a public endpoint.
func newServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           securityHeaders(handler),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// securityHeaders sets what every response should carry.
//
// Referrer-Policy matters more than it looks: without it an authorization code
// could ride along in a Referer header to wherever the browser goes next.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// systemClock is the real clock the use case reads time from.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }
