// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/audit"
	"github.com/motrice/smartcard-op/internal/domain"
)

// completeEnvironment is a configuration that should start.
func completeEnvironment() map[string]string {
	return map[string]string{
		"SMARTCARD_OP_ISSUER":                 "https://idp.example.se",
		"SMARTCARD_OP_KEY_DIR":                "/etc/smartcard-op/keys",
		"SMARTCARD_OP_EFOS_CA_BUNDLE":         "/etc/smartcard-op/efos-ca.pem",
		"SMARTCARD_OP_CLIENT_ID":              "zitadel",
		"SMARTCARD_OP_CLIENT_SECRET":          strings.Repeat("s", 43),
		"SMARTCARD_OP_REDIRECT_URIS":          "https://id.example.se/idps/callback",
		"SMARTCARD_OP_CARD_LOGIN_URL":         "https://card.idp.example.se/login",
		"SMARTCARD_OP_MIN_ASSURANCE_LEVEL":    "3",
		"SMARTCARD_OP_SYNTHETIC_EMAIL_DOMAIN": "card-noreply.example.se",
		"SMARTCARD_OP_AUDIT_HMAC_KEY":         "a-key-of-sufficient-length-here",
		"SMARTCARD_OP_TOKEN_CRYPTO_KEY":       "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
	}
}

func lookupFrom(environment map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, present := environment[name]

		return value, present
	}
}

func TestLoadConfigAcceptsACompleteEnvironment(t *testing.T) {
	t.Parallel()

	loaded, err := loadConfig(lookupFrom(completeEnvironment()))
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if loaded.Issuer != "https://idp.example.se" {
		t.Errorf("Issuer = %q", loaded.Issuer)
	}

	if loaded.MinimumAssuranceLevel != domain.AssuranceLevel3 {
		t.Errorf("MinimumAssuranceLevel = %v", loaded.MinimumAssuranceLevel)
	}

	if loaded.IssuerListen != defaultIssuerListen || loaded.CardListen != defaultCardListen {
		t.Errorf("listen addresses = %q and %q", loaded.IssuerListen, loaded.CardListen)
	}

	// The default must be the protective one.
	if loaded.AuditRedaction != audit.RedactionHashed {
		t.Errorf("AuditRedaction = %q, want hashed by default", loaded.AuditRedaction)
	}

	// Zero tolerance for a stale revocation list is the safe default.
	if loaded.CRLMaxStaleness != 0 {
		t.Errorf("CRLMaxStaleness = %v, want 0 by default", loaded.CRLMaxStaleness)
	}
}

// Every required value is required. A service that starts half-configured
// would appear to work while protecting nothing, and the failure would surface
// as a successful login by someone who should have been refused.
func TestLoadConfigRequiresEverythingItNeeds(t *testing.T) {
	t.Parallel()

	for name := range completeEnvironment() {
		t.Run("without "+name, func(t *testing.T) {
			t.Parallel()

			environment := completeEnvironment()
			delete(environment, name)

			_, err := loadConfig(lookupFrom(environment))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("the service started without %s: %v", name, err)
			}

			if !strings.Contains(err.Error(), name) {
				t.Errorf("the error does not name %s: %v", name, err)
			}
		})
	}
}

// The assurance level has no default on purpose: DIGG requires level 3 for many
// services, and guessing would quietly admit level 2 cards.
func TestLoadConfigRefusesAnUnsafeAssuranceLevel(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "1", "5", "three", "0"} {
		environment := completeEnvironment()
		environment["SMARTCARD_OP_MIN_ASSURANCE_LEVEL"] = value

		if _, err := loadConfig(lookupFrom(environment)); !errors.Is(err, ErrConfig) {
			t.Errorf("the assurance level %q was accepted", value)
		}
	}
}

// Anything a browser or Zitadel reaches must be https. The OIDC library
// permits a plaintext redirect uri for a confidential client, so refusing it is
// our own policy and belongs where it is visible.
func TestLoadConfigRefusesPlaintextURLs(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"SMARTCARD_OP_ISSUER":         "http://idp.example.se",
		"SMARTCARD_OP_CARD_LOGIN_URL": "http://card.idp.example.se/login",
		"SMARTCARD_OP_REDIRECT_URIS":  "http://id.example.se/idps/callback",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			environment := completeEnvironment()
			environment[name] = value

			if _, err := loadConfig(lookupFrom(environment)); !errors.Is(err, ErrConfig) {
				t.Errorf("a plaintext %s was accepted", name)
			}
		})
	}
}

// Hashing an identity number without a key is reversible by brute force, so
// the key is required whenever hashing is.
func TestLoadConfigRequiresAKeyForHashedRedaction(t *testing.T) {
	t.Parallel()

	environment := completeEnvironment()
	delete(environment, "SMARTCARD_OP_AUDIT_HMAC_KEY")
	environment["SMARTCARD_OP_AUDIT_REDACTION"] = "hashed"

	if _, err := loadConfig(lookupFrom(environment)); !errors.Is(err, ErrConfig) {
		t.Error("hashed redaction was accepted without a key")
	}

	// The other modes need no key.
	for _, mode := range []string{"masked", "full"} {
		environment := completeEnvironment()
		delete(environment, "SMARTCARD_OP_AUDIT_HMAC_KEY")
		environment["SMARTCARD_OP_AUDIT_REDACTION"] = mode

		if _, err := loadConfig(lookupFrom(environment)); err != nil {
			t.Errorf("%s redaction was refused without a key: %v", mode, err)
		}
	}
}

func TestLoadConfigReadsOptionalValues(t *testing.T) {
	t.Parallel()

	environment := completeEnvironment()
	environment["SMARTCARD_OP_ISSUER_LISTEN"] = ":9090"
	environment["SMARTCARD_OP_CARD_LISTEN"] = ":9091"
	environment["SMARTCARD_OP_CRL_MAX_STALENESS"] = "24h"
	environment["SMARTCARD_OP_REDIRECT_URIS"] =
		"https://id.example.se/idps/callback, https://id.example.se/ui/v2/login/idp/callback"

	loaded, err := loadConfig(lookupFrom(environment))
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if loaded.IssuerListen != ":9090" || loaded.CardListen != ":9091" {
		t.Errorf("listen addresses = %q and %q", loaded.IssuerListen, loaded.CardListen)
	}

	if loaded.CRLMaxStaleness != 24*time.Hour {
		t.Errorf("CRLMaxStaleness = %v", loaded.CRLMaxStaleness)
	}

	if len(loaded.RedirectURIs) != 2 {
		t.Errorf("%d redirect uris, want 2: %v", len(loaded.RedirectURIs), loaded.RedirectURIs)
	}
}

func TestLoadConfigValidatesTheTokenCryptoKey(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"not base64": "not base64 at all!",
		"too short":  "MDEyMzQ1Njc4OQ==",
		"too long":   "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			environment := completeEnvironment()
			environment["SMARTCARD_OP_TOKEN_CRYPTO_KEY"] = value

			if _, err := loadConfig(lookupFrom(environment)); !errors.Is(err, ErrConfig) {
				t.Errorf("an invalid crypto key was accepted: %q", value)
			}
		})
	}
}

// All problems at once, so that an operator fixes the configuration in one pass
// rather than discovering the next fault on every restart.
func TestLoadConfigReportsEveryProblemTogether(t *testing.T) {
	t.Parallel()

	_, err := loadConfig(lookupFrom(map[string]string{}))
	if err == nil {
		t.Fatal("an empty environment was accepted")
	}

	for _, name := range []string{
		"SMARTCARD_OP_ISSUER",
		"SMARTCARD_OP_KEY_DIR",
		"SMARTCARD_OP_EFOS_CA_BUNDLE",
		"SMARTCARD_OP_MIN_ASSURANCE_LEVEL",
		"SMARTCARD_OP_TOKEN_CRYPTO_KEY",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not mention %s: %v", name, err)
		}
	}
}
