// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/audit"
	"github.com/motrice/smartcard-op/internal/domain"
)

// ErrConfig wraps every rejected configuration.
var ErrConfig = errors.New("configuration")

// Environment variable names. The prefix keeps them apart from whatever else
// shares the pod.
const (
	envIssuer       = "SMARTCARD_OP_ISSUER"
	envIssuerListen = "SMARTCARD_OP_ISSUER_LISTEN"
	envCardListen   = "SMARTCARD_OP_CARD_LISTEN"
	envKeyDir       = "SMARTCARD_OP_KEY_DIR"
	envCABundle     = "SMARTCARD_OP_EFOS_CA_BUNDLE"
	envClientID     = "SMARTCARD_OP_CLIENT_ID"
	//nolint:gosec // G101: an environment variable name, not a credential
	envClientSecret    = "SMARTCARD_OP_CLIENT_SECRET"
	envRedirectURIs    = "SMARTCARD_OP_REDIRECT_URIS"
	envCardLoginURL    = "SMARTCARD_OP_CARD_LOGIN_URL"
	envAssuranceLevel  = "SMARTCARD_OP_MIN_ASSURANCE_LEVEL"
	envEmailDomain     = "SMARTCARD_OP_SYNTHETIC_EMAIL_DOMAIN"
	envCRLMaxStaleness = "SMARTCARD_OP_CRL_MAX_STALENESS"
	envAuditRedaction  = "SMARTCARD_OP_AUDIT_REDACTION"
	envAuditHMACKey    = "SMARTCARD_OP_AUDIT_HMAC_KEY"
	//nolint:gosec // G101: an environment variable name, not a credential
	envTokenCryptoKey = "SMARTCARD_OP_TOKEN_CRYPTO_KEY"
	envInstanceID     = "SMARTCARD_OP_INSTANCE_ID"
)

const (
	defaultIssuerListen = ":8080"
	defaultCardListen   = ":8081"
	// cryptoKeyLength is the key length op.Config requires for encrypting
	// opaque access tokens.
	cryptoKeyLength = 32
)

// config is the whole of the service's configuration.
type config struct {
	Issuer       string
	IssuerListen string
	CardListen   string

	KeyDir   string
	CABundle string

	ClientID     string
	ClientSecret string
	RedirectURIs []string
	CardLoginURL string

	MinimumAssuranceLevel domain.AssuranceLevel
	SyntheticEmailDomain  string
	CRLMaxStaleness       time.Duration

	AuditRedaction audit.Redaction
	AuditHMACKey   []byte

	TokenCryptoKey [cryptoKeyLength]byte
	InstanceID     string
}

// loadConfig reads the configuration from the environment and validates it.
//
// Everything is validated here, at startup, and nothing has a permissive
// default. A service that starts with a half-configured trust anchor or no
// assurance level requirement would appear to work while protecting nothing,
// and the failure would surface as a successful login by someone who should
// have been refused. Refusing to start is the only visible failure mode.
func loadConfig(lookup func(string) (string, bool)) (*config, error) {
	loaded := &config{
		IssuerListen: valueOr(lookup, envIssuerListen, defaultIssuerListen),
		CardListen:   valueOr(lookup, envCardListen, defaultCardListen),
		InstanceID:   valueOr(lookup, envInstanceID, ""),
	}

	var problems []error

	for _, required := range []struct {
		name  string
		field *string
	}{
		{envIssuer, &loaded.Issuer},
		{envKeyDir, &loaded.KeyDir},
		{envCABundle, &loaded.CABundle},
		{envClientID, &loaded.ClientID},
		{envClientSecret, &loaded.ClientSecret},
		{envCardLoginURL, &loaded.CardLoginURL},
		{envEmailDomain, &loaded.SyntheticEmailDomain},
	} {
		value, _ := lookup(required.name)
		if strings.TrimSpace(value) == "" {
			problems = append(problems, fmt.Errorf("%w: %s is required", ErrConfig, required.name))

			continue
		}

		*required.field = strings.TrimSpace(value)
	}

	problems = append(problems, loaded.readRedirectURIs(lookup)...)
	problems = append(problems, loaded.readAssuranceLevel(lookup)...)
	problems = append(problems, loaded.readStaleness(lookup)...)
	problems = append(problems, loaded.readAudit(lookup)...)
	problems = append(problems, loaded.readCryptoKey(lookup)...)
	problems = append(problems, loaded.checkURLs()...)

	if len(problems) > 0 {
		// Every problem already wraps ErrConfig, so errors.Is still finds
		// it through the join — and the operator gets the whole list in one
		// pass rather than discovering the next fault on every restart.
		return nil, errors.Join(problems...)
	}

	return loaded, nil
}

func (c *config) readRedirectURIs(lookup func(string) (string, bool)) []error {
	raw, _ := lookup(envRedirectURIs)
	if strings.TrimSpace(raw) == "" {
		return []error{fmt.Errorf("%w: %s is required", ErrConfig, envRedirectURIs)}
	}

	var problems []error

	for candidate := range strings.SplitSeq(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}

		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			problems = append(problems, fmt.Errorf(
				"%w: %s: %q must be an absolute https url",
				ErrConfig, envRedirectURIs, candidate))

			continue
		}

		c.RedirectURIs = append(c.RedirectURIs, candidate)
	}

	if len(c.RedirectURIs) == 0 && len(problems) == 0 {
		problems = append(problems, fmt.Errorf("%w: %s is required", ErrConfig, envRedirectURIs))
	}

	return problems
}

// readAssuranceLevel has no default on purpose. DIGG requires level 3 for many
// services, and guessing on the operator's behalf would mean quietly admitting
// level 2 cards where level 3 was intended.
func (c *config) readAssuranceLevel(lookup func(string) (string, bool)) []error {
	raw, _ := lookup(envAssuranceLevel)

	switch strings.TrimSpace(raw) {
	case "2":
		c.MinimumAssuranceLevel = domain.AssuranceLevel2
	case "3":
		c.MinimumAssuranceLevel = domain.AssuranceLevel3
	case "4":
		c.MinimumAssuranceLevel = domain.AssuranceLevel4
	case "":
		return []error{fmt.Errorf(
			"%w: %s is required and must be 2, 3 or 4; there is no safe default",
			ErrConfig, envAssuranceLevel)}
	default:
		return []error{fmt.Errorf("%w: %s: %q is not 2, 3 or 4", ErrConfig, envAssuranceLevel, raw)}
	}

	return nil
}

func (c *config) readStaleness(lookup func(string) (string, bool)) []error {
	raw, present := lookup(envCRLMaxStaleness)
	if !present || strings.TrimSpace(raw) == "" {
		// Zero tolerance is the safe default: a revocation list past its
		// nextUpdate says nothing about today's revocations.
		return nil
	}

	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return []error{fmt.Errorf("%w: %s: %q is not a duration: %w", ErrConfig, envCRLMaxStaleness, raw, err)}
	}

	if parsed < 0 {
		return []error{fmt.Errorf("%w: %s must not be negative", ErrConfig, envCRLMaxStaleness)}
	}

	c.CRLMaxStaleness = parsed

	return nil
}

func (c *config) readAudit(lookup func(string) (string, bool)) []error {
	raw, _ := lookup(envAuditRedaction)

	switch strings.TrimSpace(raw) {
	case "", string(audit.RedactionHashed):
		c.AuditRedaction = audit.RedactionHashed
	case string(audit.RedactionMasked):
		c.AuditRedaction = audit.RedactionMasked
	case string(audit.RedactionFull):
		c.AuditRedaction = audit.RedactionFull
	default:
		return []error{fmt.Errorf("%w: %s: %q is not hashed, masked or full", ErrConfig, envAuditRedaction, raw)}
	}

	key, _ := lookup(envAuditHMACKey)
	c.AuditHMACKey = []byte(strings.TrimSpace(key))

	if c.AuditRedaction == audit.RedactionHashed && len(c.AuditHMACKey) == 0 {
		return []error{fmt.Errorf(
			"%w: %s is required when %s is hashed",
			ErrConfig, envAuditHMACKey, envAuditRedaction)}
	}

	return nil
}

func (c *config) readCryptoKey(lookup func(string) (string, bool)) []error {
	raw, _ := lookup(envTokenCryptoKey)
	if strings.TrimSpace(raw) == "" {
		return []error{fmt.Errorf("%w: %s is required", ErrConfig, envTokenCryptoKey)}
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return []error{fmt.Errorf("%w: %s is not base64: %w", ErrConfig, envTokenCryptoKey, err)}
	}

	if len(decoded) != cryptoKeyLength {
		return []error{fmt.Errorf(
			"%w: %s decodes to %d bytes, want %d",
			ErrConfig, envTokenCryptoKey, len(decoded), cryptoKeyLength)}
	}

	copy(c.TokenCryptoKey[:], decoded)

	return nil
}

// checkURLs refuses plaintext for anything a browser or Zitadel will reach. The
// OIDC library permits an http redirect uri for a confidential client, so this
// is our own policy and has to be stated where it is visible.
func (c *config) checkURLs() []error {
	var problems []error

	for name, raw := range map[string]string{
		envIssuer:       c.Issuer,
		envCardLoginURL: c.CardLoginURL,
	} {
		if raw == "" {
			continue
		}

		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			problems = append(problems, fmt.Errorf(
				"%w: %s: %q must be an absolute https url", ErrConfig, name, raw))
		}
	}

	return problems
}

func valueOr(lookup func(string) (string, bool), name, fallback string) string {
	if value, present := lookup(name); present && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}

	return fallback
}

// environment reads the process environment, which is what main uses.
func environment(name string) (string, bool) {
	return os.LookupEnv(name)
}

// assuranceLevelText renders the level for the startup banner.
func assuranceLevelText(level domain.AssuranceLevel) string {
	return strconv.Itoa(int(level))
}
