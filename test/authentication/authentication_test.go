// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package authentication_test wires the real layers together.
//
// Every other test exercises one layer in isolation with faked ports. This one
// weaves the trust anchor, the DN reader, the revocation check and the use case
// together — the same composition cmd/smartcard-op will perform — so that a gap
// between two correct parts cannot pass unnoticed. Tests are composition roots
// and may therefore connect the real layers, as ADR 0004 states.
package authentication_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/motrice/smartcard-op/internal/adapters/efospki"
	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/app"
	"github.com/motrice/smartcard-op/internal/domain"
	"github.com/motrice/smartcard-op/internal/testutil"
)

// systemClock is the only fake: the system time. Everything else is the real
// adapter.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type collectingAuditLog struct {
	events []app.AuditEvent
}

func (c *collectingAuditLog) Write(event app.AuditEvent) {
	c.events = append(c.events, event)
}

// responder starts an OCSP responder that answers with the given status for
// every request, signed by the issuer through a real responder certificate.
func responder(
	t *testing.T,
	pki *testutil.PKI,
	responderCert *x509.Certificate,
	responderKey crypto.Signer,
	status int,
) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)

		n, _ := r.Body.Read(body)

		request, err := ocsp.ParseRequest(body[:n])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		now := time.Now()

		der, err := ocsp.CreateResponse(pki.IssuerCert, responderCert, ocsp.Response{
			Status:           status,
			SerialNumber:     request.SerialNumber,
			ThisUpdate:       now.Add(-time.Minute),
			NextUpdate:       now.Add(time.Hour),
			RevokedAt:        now.Add(-48 * time.Hour),
			RevocationReason: ocsp.KeyCompromise,
			Certificate:      responderCert,
		}, responderKey)
		if err != nil {
			t.Errorf("could not build ocsp response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	return server.URL
}

// wire assembles the use case with the real adapters.
func wire(t *testing.T, pki *testutil.PKI, auditLog *collectingAuditLog) *app.Authenticator {
	t.Helper()

	anchor, err := efospki.NewTrustAnchor(pki.BundlePEM(t))
	if err != nil {
		t.Fatalf("NewTrustAnchor returned error: %v", err)
	}

	return app.NewAuthenticator(app.Dependencies{
		TrustAnchor:       anchor,
		CertificateReader: efospki.NewReader(),
		RevocationChecker: revocation.NewChecker(
			revocation.NewOCSP(nil), revocation.NewCRL(nil, 0)),
		AuditLog:              auditLog,
		Clock:                 systemClock{},
		MinimumAssuranceLevel: domain.AssuranceLevel3,
	})
}

func TestWholeChainGrantsAValidCard(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	responderCert, responderKey := pki.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	pki.OCSPAddress = responder(t, pki, responderCert, responderKey, ocsp.Good)

	card, _ := pki.Card(t, testutil.CardOptions{})
	auditLog := &collectingAuditLog{}

	identity, err := wire(t, pki, auditLog).Authenticate(context.Background(), card)
	if err != nil {
		t.Fatalf("the whole chain rejected a correct EFOS card: %v", err)
	}

	if got := identity.PersonalIdentityNumber().String(); got != "195606019577" {
		t.Errorf("PersonalIdentityNumber = %q", got)
	}

	if got := identity.EfosID().String(); got != "EFOS-4711" {
		t.Errorf("EfosID = %q", got)
	}

	if got := identity.Name().DisplayName(); got != "Anna Andersson" {
		t.Errorf("DisplayName = %q", got)
	}

	if got := identity.AssuranceLevel(); got != domain.AssuranceLevel3 {
		t.Errorf("AssuranceLevel = %v", got)
	}

	if got := identity.OrganizationNumber().String(); got != "2021005208" {
		t.Errorf("OrganizationNumber = %q", got)
	}

	if len(auditLog.events) != 1 {
		t.Fatalf("%d audit events, want 1", len(auditLog.events))
	}

	event := auditLog.events[0]
	if !event.Granted || event.Reason != "granted" {
		t.Errorf("audit event = %+v", event)
	}

	if event.RevocationVerdict.Method != domain.RevocationMethodOCSP {
		t.Errorf("RevocationVerdict.Method = %q, want ocsp", event.RevocationVerdict.Method)
	}

	if event.RevocationVerdict.Status != domain.RevocationStatusValid {
		t.Errorf("RevocationVerdict.Status = %v", event.RevocationVerdict.Status)
	}

	if len(event.Fingerprint) != 64 {
		t.Errorf("Fingerprint = %q", event.Fingerprint)
	}
}

func TestWholeChainDeniesARevokedCard(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	responderCert, responderKey := pki.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	pki.OCSPAddress = responder(t, pki, responderCert, responderKey, ocsp.Revoked)

	card, _ := pki.Card(t, testutil.CardOptions{SerialNumber: big.NewInt(7001)})
	auditLog := &collectingAuditLog{}

	_, err := wire(t, pki, auditLog).Authenticate(context.Background(), card)
	if !errors.Is(err, app.ErrCardRevoked) {
		t.Fatalf("error = %v, want ErrCardRevoked", err)
	}

	if event := auditLog.events[0]; event.Granted || event.Reason != "revoked" {
		t.Errorf("audit event = %+v", event)
	}
}

// A level 2 card must be denied where level 3 is required — and denied by the
// domain, before the responder is even asked. That no responder is running here
// makes the ordering proved rather than asserted: were the revocation check to
// run first, the test would have failed on a connection error instead.
func TestWholeChainDeniesTooLowAssuranceLevelWithoutANetworkCall(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	pki.OCSPAddress = "http://127.0.0.1:1/nobody-is-listening"

	card, _ := pki.Card(t, testutil.CardOptions{
		PolicyOIDs:   []string{"1.2.752.146.210.2"},
		SerialNumber: big.NewInt(7002),
	})
	auditLog := &collectingAuditLog{}

	_, err := wire(t, pki, auditLog).Authenticate(context.Background(), card)
	if !errors.Is(err, domain.ErrAssuranceLevelTooLow) {
		t.Fatalf("error = %v, want ErrAssuranceLevelTooLow", err)
	}

	if event := auditLog.events[0]; event.Reason != "assurance_level_too_low" {
		t.Errorf("Reason = %q", event.Reason)
	}
}

// A card from another PKI must be stopped by the trust anchor, not by some
// later check.
func TestWholeChainDeniesCardsFromAForeignIssuer(t *testing.T) {
	t.Parallel()

	own := testutil.NewPKI(t)
	foreign := testutil.NewPKI(t)
	card, _ := foreign.Card(t, testutil.CardOptions{SerialNumber: big.NewInt(7003)})
	auditLog := &collectingAuditLog{}

	_, err := wire(t, own, auditLog).Authenticate(context.Background(), card)
	if !errors.Is(err, app.ErrCertificateChain) {
		t.Fatalf("error = %v, want ErrCertificateChain", err)
	}

	if event := auditLog.events[0]; event.Reason != "certificate_chain" {
		t.Errorf("Reason = %q", event.Reason)
	}
}

// The card's signing or encryption certificate is the most common real mistake:
// the user points at the wrong certificate in the reader's dialog. It must yield
// an intelligible denial, not a certificate fault.
func TestWholeChainDeniesACertificateWithoutSmartcardLogon(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	responderCert, responderKey := pki.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	pki.OCSPAddress = responder(t, pki, responderCert, responderKey, ocsp.Good)

	card, _ := pki.Card(t, testutil.CardOptions{
		WithoutSmartcardLogon: true,
		SerialNumber:          big.NewInt(7004),
	})
	auditLog := &collectingAuditLog{}

	_, err := wire(t, pki, auditLog).Authenticate(context.Background(), card)
	if !errors.Is(err, domain.ErrDisallowedKeyUsage) {
		t.Fatalf("error = %v, want ErrDisallowedKeyUsage", err)
	}

	if event := auditLog.events[0]; event.Reason != "disallowed_key_usage" {
		t.Errorf("Reason = %q", event.Reason)
	}
}

// The claims handed to Zitadel must be formable from what the whole chain
// produced, with every mandatory field populated.
func TestWholeChainYieldsClaimsZitadelCanCreateAUserFrom(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	responderCert, responderKey := pki.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	pki.OCSPAddress = responder(t, pki, responderCert, responderKey, ocsp.Good)

	card, _ := pki.Card(t, testutil.CardOptions{SerialNumber: big.NewInt(7005)})

	identity, err := wire(t, pki, &collectingAuditLog{}).Authenticate(
		context.Background(), card)
	if err != nil {
		t.Fatalf("the whole chain rejected a correct card: %v", err)
	}

	claims, err := app.NewClaims(identity, "card-noreply.example.se")
	if err != nil {
		t.Fatalf("NewClaims returned error: %v", err)
	}

	mandatory := map[string]string{
		"sub":                claims.Sub,
		"preferred_username": claims.PreferredUsername,
		"name":               claims.Name,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
		"email":              claims.Email,
	}
	for field, value := range mandatory {
		if value == "" {
			t.Errorf("%s is empty; Zitadel refuses to create the user", field)
		}
	}

	if claims.ACR != "http://id.elegnamnden.se/loa/1.0/loa3" {
		t.Errorf("ACR = %q", claims.ACR)
	}
}
