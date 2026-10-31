// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package efospki_test

import (
	"crypto/x509"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/efospki"
	"github.com/motrice/smartcard-op/internal/domain"
	"github.com/motrice/smartcard-op/internal/testutil"
)

// The ports are declared here rather than imported from app: the adapters
// satisfy them structurally without knowing the package that declares them. The
// assertions are made at compile time, so a changed port shape fails the build.
type (
	certificateReaderPort interface {
		Read(leaf *x509.Certificate) (domain.CertificateDetails, error)
	}

	trustAnchorPort interface {
		Verify(leaf *x509.Certificate) (issuer *x509.Certificate, err error)
	}
)

var (
	_ certificateReaderPort = (*efospki.Reader)(nil)
	_ trustAnchorPort       = (*efospki.TrustAnchor)(nil)
)

func anchor(t *testing.T, pki *testutil.PKI) *efospki.TrustAnchor {
	t.Helper()

	trustAnchor, err := efospki.NewTrustAnchor(pki.BundlePEM(t))
	if err != nil {
		t.Fatalf("NewTrustAnchor returned error: %v", err)
	}

	return trustAnchor
}

func TestTrustAnchorReturnsTheIssuerThatSignedTheCard(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	issuer, err := anchor(t, pki).Verify(card)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !issuer.Equal(pki.IssuerCert) {
		t.Errorf("issuer = %q, want %q", issuer.Subject, pki.IssuerCert.Subject)
	}
}

// The EFOS issuers carry a restricted extended key usage without serverAuth. If
// the chain is verified without passing KeyUsages explicitly, Go defaults to
// ExtKeyUsageServerAuth and the verification fails with "incompatible key
// usage" — an error that looks like a broken chain but is the caller's. The test
// CA mirrors that restriction, so this test fails if anyone removes KeyUsages
// from Verify.
func TestTrustAnchorHandlesAnIssuerWithoutServerAuth(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)

	if slices.Contains(pki.IssuerCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("the test CA carries serverAuth and so does not mirror EFOS; the test proves nothing")
	}

	card, _ := pki.Card(t, testutil.CardOptions{})
	if _, err := anchor(t, pki).Verify(card); err != nil {
		t.Fatalf("Verify returned error for an issuer without serverAuth: %v", err)
	}
}

func TestTrustAnchorRejectsCardsOutsideTheAnchor(t *testing.T) {
	t.Parallel()

	own := testutil.NewPKI(t)
	foreign := testutil.NewPKI(t)
	card, _ := foreign.Card(t, testutil.CardOptions{})

	_, err := anchor(t, own).Verify(card)
	if !errors.Is(err, efospki.ErrChainNotAnchored) {
		t.Fatalf("error = %v, want ErrChainNotAnchored", err)
	}
}

func TestTrustAnchorRejectsCardsOutsideTheValidityPeriod(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)

	cases := map[string]testutil.CardOptions{
		"expired": {
			NotBefore: now.Add(-48 * time.Hour),
			NotAfter:  now.Add(-time.Hour),
		},
		"not yet valid": {
			NotBefore: now.Add(time.Hour),
			NotAfter:  now.Add(48 * time.Hour),
		},
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			card, _ := pki.Card(t, opts)

			_, err := anchor(t, pki).Verify(card)
			if !errors.Is(err, efospki.ErrChainNotAnchored) {
				t.Fatalf("error = %v, want ErrChainNotAnchored", err)
			}
		})
	}
}

// A mis-issued CA certificate must not be able to log in. Go's Verify checks
// the chain but does not stop the leaf from being a CA itself.
func TestTrustAnchorRejectsACertificateThatIsACA(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{IsCA: true, SerialNumber: big.NewInt(5150)})

	_, err := anchor(t, pki).Verify(card)
	if !errors.Is(err, efospki.ErrUnsuitableCertificate) {
		t.Fatalf("error = %v, want ErrUnsuitableCertificate", err)
	}
}

// EFOS issues 2048-bit RSA. A weaker card belongs to an earlier era and must
// not be admitted.
func TestTrustAnchorRejectsAWeakKey(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{WeakKey: true, SerialNumber: big.NewInt(5151)})

	_, err := anchor(t, pki).Verify(card)
	if !errors.Is(err, efospki.ErrUnsuitableCertificate) {
		t.Fatalf("error = %v, want ErrUnsuitableCertificate", err)
	}
}

func TestNewTrustAnchorRejectsMalformedBundles(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)

	cases := map[string][]byte{
		"empty bundle": {},
		"not pem":      []byte("just text"),
		"pem without a certificate": []byte(
			"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"),
		"malformed der in pem": []byte(
			"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"intermediate ca only": testutil.CertPEM(t, pki.IssuerCert),
	}

	for name, bundle := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := efospki.NewTrustAnchor(bundle)
			if !errors.Is(err, efospki.ErrUnusableTrustBundle) {
				t.Errorf("error = %v, want ErrUnusableTrustBundle", err)
			}
		})
	}
}

// The bundle's contents must be reportable, so that an operator can see which
// issuers are actually trusted without reading the PEM file.
func TestTrustAnchorReportsItsContents(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	contents := anchor(t, pki).Contents()

	if len(contents.Roots) != 1 {
		t.Errorf("%d roots, want 1", len(contents.Roots))
	}

	if len(contents.Intermediates) != 1 {
		t.Errorf("%d intermediates, want 1", len(contents.Intermediates))
	}

	if len(contents.Roots) == 1 && contents.Roots[0] != pki.RootCert.Subject.String() {
		t.Errorf("root = %q", contents.Roots[0])
	}
}

func TestReaderReadsTheWholeCertificateProfile(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	got := map[string][2]string{
		"SubjectSerialNumber":   {details.SubjectSerialNumber, "195606019577"},
		"EfosID":                {details.EfosID, "EFOS-4711"},
		"GivenName":             {details.GivenName, "Anna"},
		"FamilyName":            {details.FamilyName, "Andersson"},
		"CommonName":            {details.CommonName, "Anna Andersson"},
		"Organization":          {details.Organization, "Test Agency"},
		"OrganizationNumberRaw": {details.OrganizationNumberRaw, "2021005208"},
	}
	for field, pair := range got {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
		}
	}

	if !details.HasDigitalSignature {
		t.Error("HasDigitalSignature = false")
	}

	if !details.NotBefore.Equal(card.NotBefore) {
		t.Errorf("NotBefore = %v, want %v", details.NotBefore, card.NotBefore)
	}

	if !details.NotAfter.Equal(card.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", details.NotAfter, card.NotAfter)
	}
}

// The EFOS profile requires both clientAuth and smartcardLogon. Go moves
// clientAuth into the named ExtKeyUsage field and leaves smartcardLogon in
// UnknownExtKeyUsage, since it has no constant for it. The reader must merge
// both fields into OID strings, or the domain sees only one of them and rejects
// every card.
func TestReaderMergesBothExtendedKeyUsageFields(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	for _, oid := range []string{domain.OIDClientAuth, domain.OIDSmartcardLogon} {
		if !slices.Contains(details.ExtendedKeyUsage, oid) {
			t.Errorf("ExtendedKeyUsage = %v, lacks %s", details.ExtendedKeyUsage, oid)
		}
	}
}

func TestReaderReadsThePolicyIdentifiers(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if !slices.Contains(details.PolicyOIDs, "1.2.752.146.220.3") {
		t.Errorf("PolicyOIDs = %v, lacks EFOS Person 3 CA", details.PolicyOIDs)
	}
}

// This test pins Go's behaviour, so that a future upgrade changing it shows up
// here rather than as an incomprehensible login refusal: FillFromRDNSequence
// maps OID 2.5.4.5 to the named field, but not title, givenName or surname.
func TestReaderPinsGosDNMapping(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	if card.Subject.SerialNumber != "195606019577" {
		t.Errorf("Subject.SerialNumber = %q; Go no longer maps 2.5.4.5",
			card.Subject.SerialNumber)
	}

	if len(card.Subject.ExtraNames) != 0 {
		t.Errorf("ExtraNames holds %d entries on a parsed certificate; "+
			"the reader builds on Names and would miss them",
			len(card.Subject.ExtraNames))
	}

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if details.SubjectSerialNumber != card.Subject.SerialNumber {
		t.Errorf("the reader gave %q, the named field %q",
			details.SubjectSerialNumber, card.Subject.SerialNumber)
	}
}

// A DN with two serialNumber attributes is ambiguous, and Go silently keeps the
// last one. Guessing which applies would let the outcome depend on the order
// within the certificate.
func TestReaderRejectsADuplicateSubjectSerialNumber(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		DuplicateSubjectSerialNumber: true,
		SerialNumber:                 big.NewInt(6001),
	})

	_, err := efospki.NewReader().Read(card)
	if !errors.Is(err, efospki.ErrAmbiguousDN) {
		t.Fatalf("error = %v, want ErrAmbiguousDN", err)
	}
}

// An attribute whose ASN.1 value is not a string is silently skipped by Go, and
// the named field ends up empty. Silently empty is the dangerous outcome: the
// card would then be rejected with "invalid personal identity number" instead
// of with the truth.
func TestReaderRejectsANonStringAttribute(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		NonStringSubjectSerialNumber: true,
		SerialNumber:                 big.NewInt(6002),
	})

	_, err := efospki.NewReader().Read(card)
	if !errors.Is(err, efospki.ErrUnreadableDN) {
		t.Fatalf("error = %v, want ErrUnreadableDN", err)
	}
}

// A missing title is not the reader's to reject: the domain owns the rule that
// an EFOS identifier is required, and should get to say so with its own error.
func TestReaderLeavesAMissingTitleToTheDomain(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		WithoutTitle: true,
		SerialNumber: big.NewInt(6003),
	})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if details.EfosID != "" {
		t.Errorf("EfosID = %q, want empty", details.EfosID)
	}

	_, err = domain.NewCardIdentity(details, domain.AssuranceLevel2, time.Now())
	if !errors.Is(err, domain.ErrInvalidEfosID) {
		t.Errorf("the domain gave %v, want ErrInvalidEfosID", err)
	}
}

// The EFOS profile normally carries no address, but if a certificate does carry
// one it must be picked up — then none has to be synthesised.
func TestReaderReadsEmailFromSubjectAltName(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		Email:        "anna.andersson@agency.example.se",
		SerialNumber: big.NewInt(6004),
	})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if details.Email != "anna.andersson@agency.example.se" {
		t.Errorf("Email = %q", details.Email)
	}
}

func TestReaderFlagsCardsWithoutDigitalSignature(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{
		WithoutDigitalSignature: true,
		SerialNumber:            big.NewInt(6005),
	})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	if details.HasDigitalSignature {
		t.Error("HasDigitalSignature = true for a card without it")
	}
}

func TestReaderAndDomainFitTogether(t *testing.T) {
	t.Parallel()

	pki := testutil.NewPKI(t)
	card, _ := pki.Card(t, testutil.CardOptions{})

	details, err := efospki.NewReader().Read(card)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}

	identity, err := domain.NewCardIdentity(details, domain.AssuranceLevel3, time.Now())
	if err != nil {
		t.Fatalf("the domain rejected a correct EFOS card: %v", err)
	}

	if got := identity.PersonalIdentityNumber().String(); got != "195606019577" {
		t.Errorf("PersonalIdentityNumber = %q", got)
	}

	if got := identity.AssuranceLevel(); got != domain.AssuranceLevel3 {
		t.Errorf("AssuranceLevel = %v", got)
	}
}
