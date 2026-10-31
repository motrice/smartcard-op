// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package app_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/app"
	"github.com/motrice/smartcard-op/internal/domain"
)

// Hand-written fakes for the ports. A mocking framework would make the tests
// harder to read for whoever reviews the security logic.

type fakeTrustAnchor struct {
	issuer *x509.Certificate
	err    error
	calls  int
}

func (f *fakeTrustAnchor) Verify(*x509.Certificate) (*x509.Certificate, error) {
	f.calls++

	return f.issuer, f.err
}

type fakeReader struct {
	details domain.CertificateDetails
	err     error
}

func (f *fakeReader) Read(*x509.Certificate) (domain.CertificateDetails, error) {
	return f.details, f.err
}

type fakeRevocationChecker struct {
	verdict domain.RevocationVerdict
	err     error
	calls   int
}

func (f *fakeRevocationChecker) Check(
	context.Context, *x509.Certificate, *x509.Certificate,
) (domain.RevocationVerdict, error) {
	f.calls++

	return f.verdict, f.err
}

type fakeAuditLog struct {
	events []app.AuditEvent
}

func (f *fakeAuditLog) Write(event app.AuditEvent) {
	f.events = append(f.events, event)
}

type fixedClock struct{ at time.Time }

func (f fixedClock) Now() time.Time { return f.at }

// harness is an authentication where everything is in order, so that each test
// only has to change the one thing that is its own point.
type harness struct {
	trustAnchor *fakeTrustAnchor
	reader      *fakeReader
	revocation  *fakeRevocationChecker
	auditLog    *fakeAuditLog
	auth        *app.Authenticator
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	fixture := &harness{
		trustAnchor: &fakeTrustAnchor{issuer: &x509.Certificate{}},
		reader:      &fakeReader{details: details()},
		revocation: &fakeRevocationChecker{
			verdict: domain.RevocationVerdict{
				Status:   domain.RevocationStatusValid,
				Method:   domain.RevocationMethodOCSP,
				IssuedAt: now,
			},
		},
		auditLog: &fakeAuditLog{},
	}

	fixture.auth = app.NewAuthenticator(app.Dependencies{
		TrustAnchor:           fixture.trustAnchor,
		CertificateReader:     fixture.reader,
		RevocationChecker:     fixture.revocation,
		AuditLog:              fixture.auditLog,
		Clock:                 fixedClock{at: now},
		MinimumAssuranceLevel: domain.AssuranceLevel3,
	})

	return fixture
}

func TestAuthenticateGrantsAProperCard(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)

	id, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{Raw: []byte("card")})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	if got := id.PersonalIdentityNumber().String(); got != "195606019577" {
		t.Errorf("PersonalIdentityNumber() = %q", got)
	}

	if fixture.revocation.calls != 1 {
		t.Errorf("revocation was checked %d times, want 1", fixture.revocation.calls)
	}

	if len(fixture.auditLog.events) != 1 {
		t.Fatalf("%d audit events, want 1", len(fixture.auditLog.events))
	}

	if event := fixture.auditLog.events[0]; !event.Granted {
		t.Errorf("the audit event says denied: %+v", event)
	}
}

func TestAuthenticateDeniesARevokedCard(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)
	fixture.revocation.verdict = domain.RevocationVerdict{
		Status:    domain.RevocationStatusRevoked,
		Method:    domain.RevocationMethodOCSP,
		RevokedAt: now.Add(-48 * time.Hour),
	}

	_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{})
	if !errors.Is(err, app.ErrCardRevoked) {
		t.Fatalf("error = %v, want ErrCardRevoked", err)
	}

	if event := fixture.auditLog.events[0]; event.Granted || event.Reason != "revoked" {
		t.Errorf("audit event = %+v, want denied with reason revoked", event)
	}
}

// Fail closed: a missing verdict denies. Both an "unknown" answer and a
// responder that cannot be reached must yield the same outcome.
func TestAuthenticateDeniesWhenNoRevocationVerdictArrives(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		verdict domain.RevocationVerdict
		err     error
	}{
		"responder answers unknown": {
			verdict: domain.RevocationVerdict{
				Status: domain.RevocationStatusUnknown,
				Method: domain.RevocationMethodOCSP,
			},
		},
		"responder cannot be reached": {
			err: errors.New("i/o timeout"),
		},
		"empty verdict": {},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newHarness(t)
			fixture.revocation.verdict = testCase.verdict
			fixture.revocation.err = testCase.err

			_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{})
			if !errors.Is(err, app.ErrRevocationStatusUnknown) {
				t.Fatalf("error = %v, want ErrRevocationStatusUnknown", err)
			}

			if event := fixture.auditLog.events[0]; event.Granted {
				t.Error("the audit event says granted")
			}
		})
	}
}

func TestAuthenticateDeniesAnInvalidCertificateChain(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)
	fixture.trustAnchor.err = errors.New("x509: certificate signed by unknown authority")

	_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{})
	if !errors.Is(err, app.ErrCertificateChain) {
		t.Fatalf("error = %v, want ErrCertificateChain", err)
	}

	if fixture.revocation.calls != 0 {
		t.Error("revocation was checked for a certificate outside the trust anchor")
	}
}

// The domain rules are tested before the revocation check. An expired card must
// be denied without us going out on the network first — both because it is
// pointless and so that a responder that is down cannot hide the actual fault.
func TestAuthenticateTestsDomainRulesBeforeAnyNetworkCall(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)
	broken := details()
	broken.NotAfter = now.Add(-time.Second)
	fixture.reader.details = broken

	_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{})
	if !errors.Is(err, domain.ErrCertificateOutsideValidity) {
		t.Fatalf("error = %v, want ErrCertificateOutsideValidity", err)
	}

	if fixture.revocation.calls != 0 {
		t.Errorf("revocation was checked %d times for an expired card", fixture.revocation.calls)
	}

	if event := fixture.auditLog.events[0]; event.Reason != "certificate_outside_validity" {
		t.Errorf("Reason = %q", event.Reason)
	}
}

func TestAuthenticateEnforcesTheMinimumAssuranceLevel(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)
	low := details()
	low.PolicyOIDs = []string{"1.2.752.146.210.2"} // level 2
	fixture.reader.details = low

	_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{})
	if !errors.Is(err, domain.ErrAssuranceLevelTooLow) {
		t.Fatalf("error = %v, want ErrAssuranceLevelTooLow", err)
	}
}

// Every attempt must leave exactly one audit event, whichever path the code
// took. A denial without a trace is the worst possible outcome.
func TestAuthenticateAlwaysLeavesExactlyOneAuditEvent(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*harness){
		"granted": func(*harness) {},
		"broken chain": func(f *harness) {
			f.trustAnchor.err = errors.New("x")
		},
		"unreadable certificate": func(f *harness) {
			f.reader.err = errors.New("x")
		},
		"domain rule violated": func(f *harness) {
			broken := details()
			broken.HasDigitalSignature = false
			f.reader.details = broken
		},
		"revoked": func(f *harness) {
			f.revocation.verdict = domain.RevocationVerdict{
				Status: domain.RevocationStatusRevoked,
			}
		},
		"responder down": func(f *harness) {
			f.revocation.err = errors.New("i/o timeout")
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newHarness(t)
			mutate(fixture)

			_, _ = fixture.auth.Authenticate(
				context.Background(), &x509.Certificate{Raw: []byte("c")})

			if len(fixture.auditLog.events) != 1 {
				t.Fatalf("%d audit events, want exactly 1", len(fixture.auditLog.events))
			}

			if event := fixture.auditLog.events[0]; event.Reason == "" {
				t.Error("the audit event has no reason")
			}
		})
	}
}

// The audit event must carry what an investigator needs: the fingerprint as a
// correlation key, and the revocation verdict's evidence.
func TestAuthenticateLogsTheRevocationEvidence(t *testing.T) {
	t.Parallel()

	fixture := newHarness(t)
	fixture.revocation.verdict = domain.RevocationVerdict{
		Status:    domain.RevocationStatusValid,
		Method:    domain.RevocationMethodCRL,
		IssuedAt:  now.Add(-time.Minute),
		FromCache: true,
	}

	_, err := fixture.auth.Authenticate(context.Background(), &x509.Certificate{Raw: []byte("card")})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	event := fixture.auditLog.events[0]
	if len(event.Fingerprint) != 64 {
		t.Errorf("Fingerprint = %q, want 64 hex characters", event.Fingerprint)
	}

	if event.RevocationVerdict.Method != domain.RevocationMethodCRL ||
		!event.RevocationVerdict.FromCache {
		t.Errorf("RevocationVerdict = %+v", event.RevocationVerdict)
	}

	if event.AssuranceLevel != domain.AssuranceLevel3 {
		t.Errorf("AssuranceLevel = %v", event.AssuranceLevel)
	}
}
