// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package revocation_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/domain"
	"github.com/motrice/smartcard-op/internal/testutil"
)

// revocationCheckerPort is the same shape the use case declares. That it is
// written here, rather than imported from app, is the whole point: the adapter
// satisfies the port structurally without knowing the package that declares it.
type revocationCheckerPort interface {
	Check(
		ctx context.Context,
		leaf *x509.Certificate,
		issuer *x509.Certificate,
	) (domain.RevocationVerdict, error)
}

// The assertion is made at compile time, so a changed port shape fails the
// build rather than a test that may not be run.
var _ revocationCheckerPort = (*revocation.Checker)(nil)

// fakeQuerier counts calls and answers as the test set it up to.
type fakeQuerier struct {
	verdict domain.RevocationVerdict
	err     error
	calls   int
}

func (f *fakeQuerier) Query(
	context.Context, *x509.Certificate, *x509.Certificate, string,
) (domain.RevocationVerdict, error) {
	f.calls++

	return f.verdict, f.err
}

// cardWithEndpoints returns a card carrying both an authority information
// access and a CRL distribution point.
func cardWithEndpoints(t *testing.T) (*testutil.PKI, *x509.Certificate) {
	t.Helper()

	pki := testutil.NewPKI(t)
	pki.OCSPAddress = "http://ocsp.example.test"
	pki.CRLAddress = "http://crl.example.test/person3.crl"
	card, _ := pki.Card(t, testutil.CardOptions{})

	return pki, card
}

// A binding answer from the responder is final. Falling back to the revocation
// list after an "unknown" would buy a hostile or broken responder a second
// chance by refusing to answer properly.
func TestCheckerTrustsBindingOCSPAnswers(t *testing.T) {
	t.Parallel()

	cases := map[string]domain.RevocationStatus{
		"valid":   domain.RevocationStatusValid,
		"revoked": domain.RevocationStatusRevoked,
		"unknown": domain.RevocationStatusUnknown,
	}

	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pki, card := cardWithEndpoints(t)
			responder := &fakeQuerier{verdict: domain.RevocationVerdict{
				Status:     status,
				Method:     domain.RevocationMethodOCSP,
				ValidUntil: time.Now().Add(time.Hour),
			}}
			lists := &fakeQuerier{}

			verdict, err := revocation.NewChecker(responder, lists).Check(
				context.Background(), card, pki.IssuerCert)
			if err != nil {
				t.Fatalf("Check returned error: %v", err)
			}

			if verdict.Status != status {
				t.Errorf("Status = %v, want %v", verdict.Status, status)
			}

			if lists.calls != 0 {
				t.Errorf("the revocation list was read despite a binding ocsp answer (%v)", status)
			}
		})
	}
}

func TestCheckerFallsBackToTheRevocationListOnTransportFailure(t *testing.T) {
	t.Parallel()

	pki, card := cardWithEndpoints(t)
	responder := &fakeQuerier{err: revocation.ErrResponderUnreachable}
	lists := &fakeQuerier{verdict: domain.RevocationVerdict{
		Status: domain.RevocationStatusRevoked,
		Method: domain.RevocationMethodCRL,
	}}

	verdict, err := revocation.NewChecker(responder, lists).Check(
		context.Background(), card, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if verdict.Status != domain.RevocationStatusRevoked {
		t.Errorf("Status = %v, want revoked", verdict.Status)
	}

	if verdict.Method != domain.RevocationMethodCRL {
		t.Errorf("Method = %q, want crl", verdict.Method)
	}

	if lists.calls != 1 {
		t.Errorf("the revocation list was read %d times, want 1", lists.calls)
	}
}

func TestCheckerDeniesWhenBothRoutesAreClosed(t *testing.T) {
	t.Parallel()

	pki, card := cardWithEndpoints(t)
	responder := &fakeQuerier{err: revocation.ErrResponderUnreachable}
	lists := &fakeQuerier{err: revocation.ErrResponderUnreachable}

	_, err := revocation.NewChecker(responder, lists).Check(
		context.Background(), card, pki.IssuerCert)
	if !errors.Is(err, revocation.ErrRevocationUnreachable) {
		t.Fatalf("error = %v, want ErrRevocationUnreachable", err)
	}
}

// A certificate with neither an authority information access nor a CRL
// distribution point cannot be revocation-checked at all. It must be denied,
// not read as valid.
func TestCheckerDeniesCertificatesWithoutRevocationEndpoints(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	_, err := revocation.NewChecker(&fakeQuerier{}, &fakeQuerier{}).Check(
		context.Background(), card, pki.IssuerCert)
	if !errors.Is(err, revocation.ErrNoRevocationEndpoints) {
		t.Fatalf("error = %v, want ErrNoRevocationEndpoints", err)
	}
}

// A valid verdict is cached for as long as it is itself valid, so that every
// login does not cost a network call.
func TestCheckerCachesValidVerdicts(t *testing.T) {
	t.Parallel()

	pki, card := cardWithEndpoints(t)
	responder := &fakeQuerier{verdict: domain.RevocationVerdict{
		Status:     domain.RevocationStatusValid,
		Method:     domain.RevocationMethodOCSP,
		ValidUntil: time.Now().Add(time.Hour),
	}}

	checker := revocation.NewChecker(responder, &fakeQuerier{})
	for range 3 {
		if _, err := checker.Check(
			context.Background(), card, pki.IssuerCert); err != nil {
			t.Fatalf("Check returned error: %v", err)
		}
	}

	if responder.calls != 1 {
		t.Errorf("the responder was queried %d times, want 1", responder.calls)
	}

	second, err := checker.Check(context.Background(), card, pki.IssuerCert)
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if !second.FromCache {
		t.Error("a cached verdict was not marked as cached")
	}
}

// A revoked card is final and must never be cached: caching exists to save
// network calls in the normal case, and a revoked card is not the normal case.
// Caching it would also hide a later change of mind by EFOS.
func TestCheckerNeverCachesNegativeVerdicts(t *testing.T) {
	t.Parallel()

	for name, status := range map[string]domain.RevocationStatus{
		"revoked": domain.RevocationStatusRevoked,
		"unknown": domain.RevocationStatusUnknown,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pki, card := cardWithEndpoints(t)
			responder := &fakeQuerier{verdict: domain.RevocationVerdict{
				Status:     status,
				Method:     domain.RevocationMethodOCSP,
				ValidUntil: time.Now().Add(time.Hour),
			}}

			checker := revocation.NewChecker(responder, &fakeQuerier{})
			for range 3 {
				if _, err := checker.Check(
					context.Background(), card, pki.IssuerCert); err != nil {
					t.Fatalf("Check returned error: %v", err)
				}
			}

			if responder.calls != 3 {
				t.Errorf("the responder was queried %d times, want 3", responder.calls)
			}
		})
	}
}
