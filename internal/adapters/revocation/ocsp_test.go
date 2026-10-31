// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package revocation_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/domain"
	"github.com/motrice/smartcard-op/internal/testutil"
)

// responsePlan describes how the fake responder should answer.
type responsePlan struct {
	status           int
	thisUpdate       time.Time
	nextUpdate       time.Time
	revokedAt        time.Time
	revocationReason int
	// responderCert is the certificate the response is signed with and
	// embedded as.
	responderCert *x509.Certificate
	responderKey  crypto.Signer
	// httpStatus replaces 200 when set.
	httpStatus int
	// garbage sends something that is not an OCSP response at all.
	garbage bool
}

// responder starts a fake OCSP responder answering according to the plan.
func responder(
	t *testing.T,
	pki *testutil.PKI,
	card *x509.Certificate,
	plan responsePlan,
) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if plan.httpStatus != 0 {
			w.WriteHeader(plan.httpStatus)

			return
		}

		if plan.garbage {
			_, _ = w.Write([]byte("not an ocsp response"))

			return
		}

		template := ocsp.Response{
			Status:           plan.status,
			SerialNumber:     card.SerialNumber,
			ThisUpdate:       plan.thisUpdate,
			NextUpdate:       plan.nextUpdate,
			RevokedAt:        plan.revokedAt,
			RevocationReason: plan.revocationReason,
			Certificate:      plan.responderCert,
		}

		der, err := ocsp.CreateResponse(
			pki.IssuerCert, plan.responderCert, template, plan.responderKey)
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

// harness returns a PKI, a card and a valid responder certificate.
func harness(t *testing.T) (*testutil.PKI, *x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()

	now := time.Now()
	pki := testutil.NewPKI(t)
	responderCert, responderKey := pki.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	card, _ := pki.Card(t, testutil.CardOptions{})

	return pki, card, responderCert, responderKey
}

func TestOCSPReadsTheVerdict(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		want   domain.RevocationStatus
	}{
		"good":    {ocsp.Good, domain.RevocationStatusValid},
		"revoked": {ocsp.Revoked, domain.RevocationStatusRevoked},
		"unknown": {ocsp.Unknown, domain.RevocationStatusUnknown},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			now := time.Now()
			pki, card, responderCert, responderKey := harness(t)
			address := responder(t, pki, card, responsePlan{
				status:        testCase.status,
				thisUpdate:    now.Add(-time.Minute),
				nextUpdate:    now.Add(time.Hour),
				revokedAt:     now.Add(-48 * time.Hour),
				responderCert: responderCert,
				responderKey:  responderKey,
			})

			verdict, err := revocation.NewOCSP(nil).Query(
				context.Background(), card, pki.IssuerCert, address)
			if err != nil {
				t.Fatalf("Query returned error: %v", err)
			}

			if verdict.Status != testCase.want {
				t.Errorf("Status = %v, want %v", verdict.Status, testCase.want)
			}

			if verdict.Method != domain.RevocationMethodOCSP {
				t.Errorf("Method = %q, want ocsp", verdict.Method)
			}

			if testCase.want == domain.RevocationStatusRevoked && verdict.RevokedAt.IsZero() {
				t.Error("RevokedAt is empty for a revoked card")
			}
		})
	}
}

// This is the suite's most important test. golang.org/x/crypto/ocsp verifies
// that an embedded responder certificate was signed by the issuer, but does NOT
// check that it carries id-kp-OCSPSigning in its extended key usage. Without
// that check, any card the EFOS issuer ever signed — a stolen one included —
// could sign revocation verdicts about every other card.
func TestOCSPRejectsAResponderCertificateWithoutOCSPSigning(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	withoutEKU, key := pki.ResponderCertificate(
		t, false, now.Add(-time.Hour), now.Add(24*time.Hour))

	address := responder(t, pki, card, responsePlan{
		status:        ocsp.Good,
		thisUpdate:    now.Add(-time.Minute),
		nextUpdate:    now.Add(time.Hour),
		responderCert: withoutEKU,
		responderKey:  key,
	})

	_, err := revocation.NewOCSP(nil).Query(
		context.Background(), card, pki.IssuerCert, address)
	if !errors.Is(err, revocation.ErrDisallowedResponderCertificate) {
		t.Fatalf("error = %v, want ErrDisallowedResponderCertificate", err)
	}
}

func TestOCSPRejectsAnExpiredResponderCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	expired, key := pki.ResponderCertificate(
		t, true, now.Add(-48*time.Hour), now.Add(-time.Hour))

	address := responder(t, pki, card, responsePlan{
		status:        ocsp.Good,
		thisUpdate:    now.Add(-time.Minute),
		nextUpdate:    now.Add(time.Hour),
		responderCert: expired,
		responderKey:  key,
	})

	_, err := revocation.NewOCSP(nil).Query(
		context.Background(), card, pki.IssuerCert, address)
	if !errors.Is(err, revocation.ErrDisallowedResponderCertificate) {
		t.Fatalf("error = %v, want ErrDisallowedResponderCertificate", err)
	}
}

// A response that is too old, or whose validity has lapsed, must not be
// accepted. x/crypto/ocsp supports no nonce, so the freshness check is what
// bounds replay of an old "good" — the same protection browsers rely on.
func TestOCSPRejectsStaleResponses(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		thisUpdate time.Time
		nextUpdate time.Time
	}{
		"nextUpdate has lapsed": {
			thisUpdate: time.Now().Add(-48 * time.Hour),
			nextUpdate: time.Now().Add(-24 * time.Hour),
		},
		"thisUpdate is in the future": {
			thisUpdate: time.Now().Add(24 * time.Hour),
			nextUpdate: time.Now().Add(48 * time.Hour),
		},
		"no nextUpdate and older than the cap": {
			thisUpdate: time.Now().Add(-30 * 24 * time.Hour),
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pki, card, responderCert, responderKey := harness(t)
			address := responder(t, pki, card, responsePlan{
				status:        ocsp.Good,
				thisUpdate:    testCase.thisUpdate,
				nextUpdate:    testCase.nextUpdate,
				responderCert: responderCert,
				responderKey:  responderKey,
			})

			_, err := revocation.NewOCSP(nil).Query(
				context.Background(), card, pki.IssuerCert, address)
			if !errors.Is(err, revocation.ErrStaleResponse) {
				t.Fatalf("error = %v, want ErrStaleResponse", err)
			}
		})
	}
}

// A responder that cannot be reached must yield a transport error,
// distinguishable from a binding negative answer: only transport errors may
// lead on to the CRL fallback.
func TestOCSPDistinguishesTransportFailureFromTheVerdict(t *testing.T) {
	t.Parallel()

	cases := map[string]responsePlan{
		"five hundred":     {httpStatus: http.StatusInternalServerError},
		"garbage response": {garbage: true},
	}

	for name, plan := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pki, card, _, _ := harness(t)
			address := responder(t, pki, card, plan)

			_, err := revocation.NewOCSP(nil).Query(
				context.Background(), card, pki.IssuerCert, address)
			if !errors.Is(err, revocation.ErrResponderUnreachable) {
				t.Fatalf("error = %v, want ErrResponderUnreachable", err)
			}
		})
	}
}

func TestOCSPRejectsResponsesFromAForeignIssuer(t *testing.T) {
	t.Parallel()

	now := time.Now()
	own := testutil.NewPKI(t)
	card, _ := own.Card(t, testutil.CardOptions{})

	// The response is signed by an entirely different hierarchy.
	foreign := testutil.NewPKI(t)
	responderCert, key := foreign.ResponderCertificate(
		t, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	address := responder(t, foreign, card, responsePlan{
		status:        ocsp.Good,
		thisUpdate:    now.Add(-time.Minute),
		nextUpdate:    now.Add(time.Hour),
		responderCert: responderCert,
		responderKey:  key,
	})

	_, err := revocation.NewOCSP(nil).Query(
		context.Background(), card, own.IssuerCert, address)
	if err == nil {
		t.Fatal("a response from a foreign issuer was accepted")
	}
}
