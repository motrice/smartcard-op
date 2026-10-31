// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package revocation_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/domain"
	"github.com/motrice/smartcard-op/internal/testutil"
)

type listPlan struct {
	revoked    []*big.Int
	thisUpdate time.Time
	nextUpdate time.Time
	// signWith replaces the issuer's key, to exercise the signature check.
	signWith   crypto.Signer
	httpStatus int
	garbage    bool
}

// revocationList starts a server that serves a revocation list according to the
// plan, and counts how many times it was fetched.
func revocationList(t *testing.T, pki *testutil.PKI, plan listPlan) (string, *atomic.Int64) {
	t.Helper()

	var fetches atomic.Int64

	if plan.thisUpdate.IsZero() {
		plan.thisUpdate = time.Now().Add(-10 * time.Minute)
	}

	if plan.nextUpdate.IsZero() {
		plan.nextUpdate = time.Now().Add(72 * time.Hour)
	}

	signer := crypto.Signer(pki.IssuerKey)
	if plan.signWith != nil {
		signer = plan.signWith
	}

	entries := make([]x509.RevocationListEntry, 0, len(plan.revoked))
	for _, serial := range plan.revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-48 * time.Hour),
			ReasonCode:     1,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(7),
		ThisUpdate:                plan.thisUpdate,
		NextUpdate:                plan.nextUpdate,
		RevokedCertificateEntries: entries,
	}, pki.IssuerCert, signer)
	if err != nil {
		t.Fatalf("could not build revocation list: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)

		if plan.httpStatus != 0 {
			w.WriteHeader(plan.httpStatus)

			return
		}

		if plan.garbage {
			_, _ = w.Write([]byte("not a revocation list"))

			return
		}

		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)

	return server.URL, &fetches
}

func TestCRLReadsRevocationStatus(t *testing.T) {
	t.Parallel()

	t.Run("the card is on the list", func(t *testing.T) {
		t.Parallel()

		pki := testutil.NewPKI(t)
		card, _ := pki.Card(t, testutil.CardOptions{SerialNumber: big.NewInt(4711)})
		address, _ := revocationList(t, pki, listPlan{revoked: []*big.Int{big.NewInt(4711)}})

		verdict, err := revocation.NewCRL(nil, 0).Query(
			context.Background(), card, pki.IssuerCert, address)
		if err != nil {
			t.Fatalf("Query returned error: %v", err)
		}

		if verdict.Status != domain.RevocationStatusRevoked {
			t.Errorf("Status = %v, want revoked", verdict.Status)
		}

		if verdict.Method != domain.RevocationMethodCRL {
			t.Errorf("Method = %q, want crl", verdict.Method)
		}

		if verdict.RevokedAt.IsZero() {
			t.Error("RevokedAt is empty")
		}

		if verdict.Reason != 1 {
			t.Errorf("Reason = %d, want 1", verdict.Reason)
		}
	})

	t.Run("the card is not on the list", func(t *testing.T) {
		t.Parallel()

		pki := testutil.NewPKI(t)
		card, _ := pki.Card(t, testutil.CardOptions{SerialNumber: big.NewInt(4711)})
		address, _ := revocationList(t, pki, listPlan{revoked: []*big.Int{big.NewInt(999)}})

		verdict, err := revocation.NewCRL(nil, 0).Query(
			context.Background(), card, pki.IssuerCert, address)
		if err != nil {
			t.Fatalf("Query returned error: %v", err)
		}

		if verdict.Status != domain.RevocationStatusValid {
			t.Errorf("Status = %v, want valid", verdict.Status)
		}
	})
}

// A revocation list is worth something only if the signature holds. Without the
// check, anyone able to answer on the CRL address could serve an empty list and
// thereby un-revoke every stolen card.
func TestCRLRejectsAnIncorrectlySignedList(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	foreign := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	address, _ := revocationList(t, pki, listPlan{signWith: foreign.IssuerKey})

	_, err := revocation.NewCRL(nil, 0).Query(
		context.Background(), card, pki.IssuerCert, address)
	if !errors.Is(err, revocation.ErrUntrustedCRL) {
		t.Fatalf("error = %v, want ErrUntrustedCRL", err)
	}
}

// EFOS issues a new list at least every thirty minutes with nextUpdate 72 hours
// out. A list whose nextUpdate has lapsed says nothing about today's
// revocations.
func TestCRLRejectsAStaleList(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	address, _ := revocationList(t, pki, listPlan{
		thisUpdate: time.Now().Add(-96 * time.Hour),
		nextUpdate: time.Now().Add(-24 * time.Hour),
	})

	_, err := revocation.NewCRL(nil, 0).Query(
		context.Background(), card, pki.IssuerCert, address)
	if !errors.Is(err, revocation.ErrStaleCRL) {
		t.Fatalf("error = %v, want ErrStaleCRL", err)
	}
}

// The staleness budget exists so that an operator can widen the window during a
// prolonged EFOS outage — but only expressly, logged and reviewably.
func TestCRLAcceptsAListWithinTheStalenessBudget(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	address, _ := revocationList(t, pki, listPlan{
		thisUpdate: time.Now().Add(-80 * time.Hour),
		nextUpdate: time.Now().Add(-8 * time.Hour),
	})

	_, err := revocation.NewCRL(nil, 24*time.Hour).Query(
		context.Background(), card, pki.IssuerCert, address)
	if err != nil {
		t.Fatalf("a list eight hours past nextUpdate was rejected with a 24h budget: %v", err)
	}

	_, err = revocation.NewCRL(nil, 4*time.Hour).Query(
		context.Background(), card, pki.IssuerCert, address)
	if !errors.Is(err, revocation.ErrStaleCRL) {
		t.Error("a 4h budget accepted a list eight hours past nextUpdate")
	}
}

func TestCRLDistinguishesTransportFailureFromTheVerdict(t *testing.T) {
	t.Parallel()

	cases := map[string]listPlan{
		"five hundred":     {httpStatus: http.StatusInternalServerError},
		"garbage response": {garbage: true},
	}

	for name, plan := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pki := testutil.NewPKI(t)
			card, _ := pki.Card(t, testutil.CardOptions{})
			address, _ := revocationList(t, pki, plan)

			_, err := revocation.NewCRL(nil, 0).Query(
				context.Background(), card, pki.IssuerCert, address)
			if !errors.Is(err, revocation.ErrResponderUnreachable) {
				t.Fatalf("error = %v, want ErrResponderUnreachable", err)
			}
		})
	}
}

// The revocation list is large and would be fetched on every login if we did
// not cache it. The cache should hold for as long as the list itself is valid.
func TestCRLIsCachedWhileTheListIsValid(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	address, fetches := revocationList(t, pki, listPlan{})

	checker := revocation.NewCRL(nil, 0)
	for range 3 {
		if _, err := checker.Query(
			context.Background(), card, pki.IssuerCert, address); err != nil {
			t.Fatalf("Query returned error: %v", err)
		}
	}

	if got := fetches.Load(); got != 1 {
		t.Errorf("the revocation list was fetched %d times, want 1", got)
	}
}

// A cached verdict must be recognisable as cached, so that the audit log can
// show the answer did not come straight from EFOS.
func TestCRLMarksCachedVerdicts(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})
	address, _ := revocationList(t, pki, listPlan{})

	checker := revocation.NewCRL(nil, 0)

	first, err := checker.Query(context.Background(), card, pki.IssuerCert, address)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if first.FromCache {
		t.Error("the first verdict was marked as cached")
	}

	second, err := checker.Query(context.Background(), card, pki.IssuerCert, address)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if !second.FromCache {
		t.Error("the second verdict was not marked as cached")
	}
}
