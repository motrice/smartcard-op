// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package testutil builds a test PKI that mirrors the EFOS certificate
// profile.
//
// The package is test infrastructure and is exempt from the layer rules.
// Fidelity to the real profile is the whole point: the value of the entire test
// suite rests on these cards looking like real EFOS cards. As soon as a real
// EFOS test card is available it should be dumped with `openssl x509 -text` and
// diffed against what this factory produces.
package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

// Object identifiers from the EFOS profile.
var (
	oidTitle        = asn1.ObjectIdentifier{2, 5, 4, 12}
	oidGivenName    = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname      = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidCardNumber   = asn1.ObjectIdentifier{1, 2, 752, 34, 2, 1}

	// OIDSmartcardLogon is szOID_KP_SMARTCARD_LOGON.
	OIDSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	// OIDOCSPSigning is id-kp-OCSPSigning.
	OIDOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// OIDPolicyLevel3 is EFOS Person 3 CA v1, expressed as a string because the
// certificate's Policies field now takes x509.OID values.
const OIDPolicyLevel3 = "1.2.752.146.220.3"

// Key generation is the most expensive thing in the test suite. Keys are
// therefore cached in a pool, but every PKI gets its **own** — two PKIs sharing
// keys would silently sabotage every test that claims to exercise a foreign
// issuer, because the signature check would then verify with the right key
// anyway.
var (
	poolMutex sync.Mutex
	keyPool   []*rsa.PrivateKey
	nextKey   int
)

// freshKeys returns n keys that no other PKI in the process uses.
func freshKeys(t *testing.T, n int) []*rsa.PrivateKey {
	t.Helper()

	poolMutex.Lock()
	defer poolMutex.Unlock()

	for len(keyPool) < nextKey+n {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("testutil: could not generate key: %v", err)
		}

		keyPool = append(keyPool, key)
	}

	issued := keyPool[nextKey : nextKey+n]
	nextKey += n

	return issued
}

// PKI is a two-level hierarchy mirroring EFOS: a root and an issuing CA.
type PKI struct {
	RootCert   *x509.Certificate
	RootKey    *rsa.PrivateKey
	IssuerCert *x509.Certificate
	IssuerKey  *rsa.PrivateKey

	// OCSPAddress and CRLAddress are written into the cards as the AIA and
	// the CRL distribution point respectively.
	OCSPAddress string
	CRLAddress  string

	cardKey      *rsa.PrivateKey
	responderKey *rsa.PrivateKey
}

// NewPKI builds the root and the issuer.
func NewPKI(t *testing.T) *PKI {
	t.Helper()

	now := time.Now()
	keys := freshKeys(t, 4)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Swedish Public Sector Internal Root CA v1 (test)"},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootCert := sign(t, rootTemplate, rootTemplate, &keys[0].PublicKey, keys[0])

	// The extended key usage mirrors the real EFOS issuers, as measured
	// against aiasat.efos.se: clientAuth, emailProtection and OCSPSigning,
	// plus smartcardLogon and document signing as unknown OIDs — and **no
	// serverAuth**.
	//
	// The fidelity is not cosmetic. Verifying a chain without passing
	// KeyUsages gets Go's default of ExtKeyUsageServerAuth, and the
	// verification then fails with "incompatible key usage". With an issuer
	// that lacks serverAuth the test suite catches that mistake; with an
	// issuer carrying no extended key usage at all it would pass unnoticed.
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Swedish Public Sector Person 3 CA v1 (test)",
			Organization: []string{"Swedish Social Insurance Agency"},
			Country:      []string{"SE"},
		},
		NotBefore: now.Add(-180 * 24 * time.Hour),
		NotAfter:  now.Add(180 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageOCSPSigning,
		},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			OIDSmartcardLogon,
			{1, 3, 6, 1, 4, 1, 311, 10, 3, 12},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerCert := sign(t, issuerTemplate, rootCert, &keys[1].PublicKey, keys[0])

	return &PKI{
		RootCert:     rootCert,
		RootKey:      keys[0],
		IssuerCert:   issuerCert,
		IssuerKey:    keys[1],
		cardKey:      keys[2],
		responderKey: keys[3],
	}
}

// BundlePEM returns the root and the issuer as a PEM bundle, the way a trust
// anchor expects to read them from a mounted ConfigMap.
func (p *PKI) BundlePEM(t *testing.T) []byte {
	t.Helper()

	certificates := []*x509.Certificate{p.RootCert, p.IssuerCert}

	bundle := make([]byte, 0, len(certificates)*2048)
	for _, cert := range certificates {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	return bundle
}

// CertPEM returns a single certificate as PEM.
func CertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// CardOptions describes deviations from an otherwise correct EFOS card.
type CardOptions struct {
	PersonalIdentityNumber string
	EfosID                 string
	GivenName              string
	FamilyName             string
	CommonName             string

	// WithoutClientAuth omits clientAuth from the extended key usage.
	WithoutClientAuth bool
	// WithoutSmartcardLogon omits smartcardLogon from the extended key
	// usage.
	WithoutSmartcardLogon bool
	// WithoutDigitalSignature omits digitalSignature from the key usage.
	WithoutDigitalSignature bool
	// PolicyOIDs replaces the certificate's policy identifiers.
	PolicyOIDs []string
	// NotBefore and NotAfter replace the validity window.
	NotBefore time.Time
	NotAfter  time.Time
	// SerialNumber replaces the certificate's own serial number.
	SerialNumber *big.Int
	// WeakKey gives the card a 1024-bit key.
	WeakKey bool
	// IsCA sets basicConstraints CA:TRUE on the card.
	IsCA bool
	// DuplicateSubjectSerialNumber writes subject:serialNumber twice. Go
	// then silently keeps the last one, which a reader must reject.
	DuplicateSubjectSerialNumber bool
	// NonStringSubjectSerialNumber writes subject:serialNumber as an ASN.1
	// integer instead of a string. Go then leaves the named field empty
	// without complaining.
	NonStringSubjectSerialNumber bool
	// Email is added as an rfc822Name in subjectAltName.
	Email string
	// WithoutTitle omits subject:title.
	WithoutTitle bool
}

// Card returns an EFOS-like authentication certificate.
func (p *PKI) Card(t *testing.T, opts CardOptions) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	applyDefaults(&opts, time.Now())

	extendedKeyUsage := []asn1.ObjectIdentifier{}
	if !opts.WithoutClientAuth {
		extendedKeyUsage = append(
			extendedKeyUsage, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})
	}

	if !opts.WithoutSmartcardLogon {
		extendedKeyUsage = append(extendedKeyUsage, OIDSmartcardLogon)
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if opts.WithoutDigitalSignature {
		keyUsage = x509.KeyUsageKeyEncipherment
	}

	extra := make([]pkix.AttributeTypeAndValue, 0, 5)
	if !opts.WithoutTitle {
		extra = append(extra, pkix.AttributeTypeAndValue{Type: oidTitle, Value: opts.EfosID})
	}

	extra = append(extra,
		pkix.AttributeTypeAndValue{Type: oidGivenName, Value: opts.GivenName},
		pkix.AttributeTypeAndValue{Type: oidSurname, Value: opts.FamilyName},
	)

	subject := pkix.Name{
		CommonName:         opts.CommonName,
		SerialNumber:       opts.PersonalIdentityNumber,
		Organization:       []string{"Test Agency"},
		OrganizationalUnit: []string{"2021005208"},
		Locality:           []string{"Stockholm"},
		Country:            []string{"SE"},
	}

	switch {
	case opts.NonStringSubjectSerialNumber:
		// An ASN.1 integer where a string is expected. Go's
		// FillFromRDNSequence silently skips the value, so the named
		// field ends up empty.
		subject.SerialNumber = ""

		extra = append(extra, pkix.AttributeTypeAndValue{Type: oidSerialNumber, Value: 4711})
	case opts.DuplicateSubjectSerialNumber:
		// Both entries must live in ExtraNames. pkix.Name.appendRDNs
		// skips the named field when the same OID is already there, so
		// one ExtraNames entry plus the named field yields only a single
		// value — not the duplicate the test needs.
		subject.SerialNumber = ""

		extra = append(extra,
			pkix.AttributeTypeAndValue{
				Type: oidSerialNumber, Value: opts.PersonalIdentityNumber,
			},
			pkix.AttributeTypeAndValue{Type: oidSerialNumber, Value: "190001019802"},
		)
	}

	subject.ExtraNames = extra

	// Policies rather than the deprecated PolicyIdentifiers: since Go 1.24
	// the latter is ignored on creation (godebug x509usepolicies).
	policies := make([]x509.OID, 0, len(opts.PolicyOIDs))

	for _, raw := range opts.PolicyOIDs {
		oid, err := x509.ParseOID(raw)
		if err != nil {
			t.Fatalf("testutil: %q is not a valid oid: %v", raw, err)
		}

		policies = append(policies, oid)
	}

	template := &x509.Certificate{
		SerialNumber:       opts.SerialNumber,
		Subject:            subject,
		NotBefore:          opts.NotBefore,
		NotAfter:           opts.NotAfter,
		KeyUsage:           keyUsage,
		UnknownExtKeyUsage: extendedKeyUsage,
		Policies:           policies,
		ExtraExtensions: []pkix.Extension{
			{Id: oidCardNumber, Value: []byte("1234567890123456789")},
		},
	}

	if opts.Email != "" {
		template.EmailAddresses = []string{opts.Email}
	}

	if opts.IsCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	if p.OCSPAddress != "" {
		template.OCSPServer = []string{p.OCSPAddress}
	}

	if p.CRLAddress != "" {
		template.CRLDistributionPoints = []string{p.CRLAddress}
	}

	key := p.cardKey

	if opts.WeakKey {
		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("testutil: could not generate weak key: %v", err)
		}

		key = weak
	}

	return sign(t, template, p.IssuerCert, &key.PublicKey, p.IssuerKey), key
}

// ResponderCertificate returns a certificate for signing OCSP responses.
//
// withOCSPSigning controls whether id-kp-OCSPSigning is present in the extended
// key usage. A responder certificate without it must not be accepted:
// otherwise any card the issuer ever signed — a stolen one included — could
// sign revocation verdicts about every other card.
func (p *PKI) ResponderCertificate(
	t *testing.T,
	withOCSPSigning bool,
	notBefore, notAfter time.Time,
) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	extendedKeyUsage := []asn1.ObjectIdentifier{}
	if withOCSPSigning {
		extendedKeyUsage = append(extendedKeyUsage, OIDOCSPSigning)
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(99),
		Subject:            pkix.Name{CommonName: "EFOS OCSP Responder (test)"},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: extendedKeyUsage,
	}

	return sign(
		t, template, p.IssuerCert, &p.responderKey.PublicKey, p.IssuerKey), p.responderKey
}

func applyDefaults(opts *CardOptions, now time.Time) {
	if opts.PersonalIdentityNumber == "" {
		opts.PersonalIdentityNumber = "195606019577"
	}

	if opts.EfosID == "" {
		opts.EfosID = "EFOS-4711"
	}

	if opts.GivenName == "" {
		opts.GivenName = "Anna"
	}

	if opts.FamilyName == "" {
		opts.FamilyName = "Andersson"
	}

	if opts.CommonName == "" {
		opts.CommonName = "Anna Andersson"
	}

	if opts.PolicyOIDs == nil {
		opts.PolicyOIDs = []string{OIDPolicyLevel3}
	}

	if opts.NotBefore.IsZero() {
		opts.NotBefore = now.Add(-24 * time.Hour)
	}

	if opts.NotAfter.IsZero() {
		opts.NotAfter = now.Add(365 * 24 * time.Hour)
	}

	if opts.SerialNumber == nil {
		opts.SerialNumber = big.NewInt(4711)
	}
}

func sign(
	t *testing.T,
	template, issuer *x509.Certificate,
	public *rsa.PublicKey,
	key *rsa.PrivateKey,
) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, key)
	if err != nil {
		t.Fatalf("testutil: could not sign certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testutil: could not parse own certificate: %v", err)
	}

	return cert
}
