// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

//go:build integration

// Integration tests against the EFOS test environment (SAT).
//
// They reach Försäkringskassan's public AIA and CRL services over the network
// and therefore run on a schedule rather than per pull request: EFOS
// maintenance must not be able to fail a build. Their value is that they test
// our parsing against **real** EFOS data rather than against fixtures we made
// up ourselves — everything else in the suite rests on assumptions about the
// profile until a real card has been in a reader.
package revocation_test

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/domain"
)

const (
	satAIA  = "http://aiasat.efos.se/"
	satCRL  = "http://crlsat.efos.se/"
	satOCSP = "http://ocspsat.efos.se"
)

// satIssuers are the issuing CAs in the test environment whose person
// certificates concern us.
var satIssuers = []string{
	"SwedishPublicSectorPerson2CASATv1",
	"SwedishPublicSectorPerson3CASATv1",
	"SwedishPublicSectorPerson4CASATv1",
}

func fetch(t *testing.T, address string) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		t.Fatalf("could not build request for %s: %v", address, err)
	}

	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		t.Skipf("the EFOS test environment could not be reached (%s): %v", address, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Skipf("the EFOS test environment answered %s for %s", response.Status, address)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		t.Fatalf("could not read the response from %s: %v", address, err)
	}

	return body
}

// The root and the issuing CAs must parse, and the chain must hold together.
//
// KeyUsages has to be given explicitly. Left out, Go defaults to
// ExtKeyUsageServerAuth, and the EFOS issuers carry a **restricted** extended
// key usage without serverAuth — the verification then fails with "incompatible
// key usage", which looks like a broken chain but is our own mistake.
func TestEFOSSATChainHoldsTogether(t *testing.T) {
	rootDER := fetch(t, satAIA+"SwedishPublicSectorInternalRootCASATv1.crt")

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("the root could not be parsed: %v", err)
	}

	t.Logf("root: %s", root.Subject)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	for _, name := range satIssuers {
		t.Run(name, func(t *testing.T) {
			issuerDER := fetch(t, satAIA+name+".crt")

			issuer, err := x509.ParseCertificate(issuerDER)
			if err != nil {
				t.Fatalf("%s could not be parsed: %v", name, err)
			}

			if _, err := issuer.Verify(x509.VerifyOptions{
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err != nil {
				t.Errorf("%s cannot be tied to the root: %v", name, err)
			}

			t.Logf("%s: subject=%q eku=%v unknown-eku=%v policies=%v ocsp=%v",
				name, issuer.Subject, issuer.ExtKeyUsage,
				issuer.UnknownExtKeyUsage, issuer.Policies, issuer.OCSPServer)
		})
	}
}

// The EFOS issuers' key usage is a precondition for the whole solution, so it is
// watched.
//
// clientAuth must be present, or no card under the issuer can be verified for
// login. And the issuer permits OCSPSigning, meaning it can delegate revocation
// verdicts — which makes the check of the responder certificate's extended key
// usage in ocsp.go anything but theoretical: without it, any card carrying that
// usage could answer for everyone else's revocation status.
func TestEFOSSATIssuerKeyUsageIsUnchanged(t *testing.T) {
	for _, name := range satIssuers {
		t.Run(name, func(t *testing.T) {
			issuerDER := fetch(t, satAIA+name+".crt")

			issuer, err := x509.ParseCertificate(issuerDER)
			if err != nil {
				t.Fatalf("%s could not be parsed: %v", name, err)
			}

			if !slices.Contains(issuer.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
				t.Error("the issuer no longer permits clientAuth; no card can be verified")
			}

			if !slices.Contains(issuer.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
				t.Log("the issuer no longer permits OCSPSigning; delegated verdicts " +
					"then do not occur, but the check must stay in place")
			}

			if issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
				t.Error("the issuer may not sign revocation lists")
			}
		})
	}
}

// The revocation lists must parse with the same code the adapter uses, and the
// signature must be tied to the issuer that issued them. This is the only test
// exercising our CRL reading against real EFOS data.
func TestEFOSSATRevocationListsVerify(t *testing.T) {
	for _, name := range satIssuers {
		t.Run(name, func(t *testing.T) {
			issuerDER := fetch(t, satAIA+name+".crt")

			issuer, err := x509.ParseCertificate(issuerDER)
			if err != nil {
				t.Fatalf("%s could not be parsed: %v", name, err)
			}

			listDER := fetch(t, satCRL+name+".crl")

			list, err := x509.ParseRevocationList(listDER)
			if err != nil {
				t.Fatalf("the revocation list for %s could not be parsed: %v", name, err)
			}

			if err := list.CheckSignatureFrom(issuer); err != nil {
				t.Errorf("the revocation list for %s cannot be verified against the issuer: %v",
					name, err)
			}

			if list.NextUpdate.IsZero() {
				t.Error("the revocation list has no nextUpdate; currency cannot be checked")
			}

			if !time.Now().Before(list.NextUpdate) {
				t.Errorf("the revocation list was valid until %s and is therefore stale now",
					list.NextUpdate.Format(time.RFC3339))
			}

			// EFOS CP section 4.9.7: a new list at least every thirty
			// minutes, nextUpdate 72 hours out. A deviation means a
			// precondition for the staleness budget has changed.
			window := list.NextUpdate.Sub(list.ThisUpdate)
			t.Logf("%s: %d revoked, thisUpdate=%s nextUpdate=%s window=%s",
				name, len(list.RevokedCertificateEntries),
				list.ThisUpdate.Format(time.RFC3339),
				list.NextUpdate.Format(time.RFC3339), window)

			if window > 96*time.Hour {
				t.Errorf("the validity window is %s, longer than the 72 hours the CP states",
					window)
			}
		})
	}
}

// The test environment's responder must answer "revoked" about a serial number
// we took from its own revocation list.
//
// This is the strongest test possible without a real card in a reader: it
// exercises the whole OCSP path — request, signature verification, the check of
// the responder certificate's extended key usage and the freshness check —
// against Försäkringskassan's actual service, and against a certificate we know
// is revoked.
func TestEFOSSATResponderAnswersAboutARevokedCertificate(t *testing.T) {
	const issuerName = "SwedishPublicSectorPerson3CASATv1"

	issuerDER := fetch(t, satAIA+issuerName+".crt")

	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("the issuer could not be parsed: %v", err)
	}

	listDER := fetch(t, satCRL+issuerName+".crl")

	list, err := x509.ParseRevocationList(listDER)
	if err != nil {
		t.Fatalf("the revocation list could not be parsed: %v", err)
	}

	if len(list.RevokedCertificateEntries) == 0 {
		t.Skip("the revocation list is empty; no revoked serial number to ask about")
	}

	revoked := list.RevokedCertificateEntries[0]

	// ocsp.CreateRequest needs only the card's serial number; the issuer's
	// name and key are hashed from the issuer certificate. We have no card,
	// but we know a serial number that is revoked.
	stub := &x509.Certificate{SerialNumber: revoked.SerialNumber}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verdict, err := revocation.NewOCSP(nil).Query(ctx, stub, issuer, satOCSP)
	if err != nil {
		t.Skipf("the EFOS test responder could not be reached: %v", err)
	}

	if verdict.Status != domain.RevocationStatusRevoked {
		t.Errorf("Status = %v for serial number %s, which is on the revocation list",
			verdict.Status, revoked.SerialNumber)
	}

	t.Logf("responder: status=%v revoked=%s reason=%d issued=%s valid until=%s",
		verdict.Status, verdict.RevokedAt.Format(time.RFC3339), verdict.Reason,
		verdict.IssuedAt.Format(time.RFC3339), verdict.ValidUntil.Format(time.RFC3339))
}
