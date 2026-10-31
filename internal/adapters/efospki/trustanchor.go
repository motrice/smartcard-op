// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package efospki ties a client certificate to EFOS and reads out its details.
//
// The package satisfies two ports the use case declares — the trust anchor and
// the certificate reader — structurally, without importing the package that
// declares them.
package efospki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

var (
	// ErrUnusableTrustBundle wraps a CA bundle that cannot be used.
	ErrUnusableTrustBundle = errors.New("unusable trust bundle")
	// ErrChainNotAnchored wraps certificates that cannot be tied to a
	// trusted EFOS issuer.
	ErrChainNotAnchored = errors.New("the certificate chain cannot be tied to the anchor")
	// ErrUnsuitableCertificate wraps certificates that do hang under the
	// anchor but must not be used for login.
	ErrUnsuitableCertificate = errors.New("the certificate is unsuitable for login")
)

// minimumRSAKeySize is the smallest RSA key we accept. EFOS issues 2048-bit
// keys; anything weaker belongs to an earlier era.
const minimumRSAKeySize = 2048

// allowedSignatureAlgorithms are the algorithms an EFOS card may be signed
// with. The list is an express allowance rather than a ban on known-weak ones,
// so that a newly weakened algorithm cannot slip in through forgetfulness.
var allowedSignatureAlgorithms = []x509.SignatureAlgorithm{
	x509.SHA256WithRSA,
	x509.SHA384WithRSA,
	x509.SHA512WithRSA,
	x509.SHA256WithRSAPSS,
	x509.SHA384WithRSAPSS,
	x509.SHA512WithRSAPSS,
	x509.ECDSAWithSHA256,
	x509.ECDSAWithSHA384,
	x509.ECDSAWithSHA512,
}

// TrustAnchor verifies the chain against the trusted EFOS issuers.
type TrustAnchor struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	rootNames     []string
	issuerNames   []string
	now           func() time.Time
}

// NewTrustAnchor reads a PEM bundle of EFOS root and issuer certificates, as
// published on aia.efos.se.
//
// Self-signed certificates become roots, the rest intermediates. At least one
// root is required: a bundle of intermediates alone cannot anchor anything, and
// starting with such a bundle would mean believing oneself protected without
// being so.
func NewTrustAnchor(bundle []byte) (*TrustAnchor, error) {
	anchor := &TrustAnchor{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		now:           time.Now,
	}

	rest := bundle
	found := 0

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: a certificate could not be parsed: %w", ErrUnusableTrustBundle, err)
		}

		found++

		if cert.Subject.String() == cert.Issuer.String() {
			anchor.roots.AddCert(cert)
			anchor.rootNames = append(anchor.rootNames, cert.Subject.String())

			continue
		}

		anchor.intermediates.AddCert(cert)
		anchor.issuerNames = append(anchor.issuerNames, cert.Subject.String())
	}

	if found == 0 {
		return nil, fmt.Errorf(
			"%w: the bundle contains no certificate", ErrUnusableTrustBundle)
	}

	if len(anchor.rootNames) == 0 {
		return nil, fmt.Errorf(
			"%w: the bundle has no root certificate and cannot anchor a chain",
			ErrUnusableTrustBundle)
	}

	return anchor, nil
}

// Verify ties the card to the anchor and returns the issuer that signed it.
//
// The issuer is needed in order to ask EFOS about that specific certificate's
// revocation status, and it must be obtained here — never from the chain the
// client itself presented, which is attacker-controlled.
func (t *TrustAnchor) Verify(card *x509.Certificate) (*x509.Certificate, error) {
	if card == nil {
		return nil, fmt.Errorf("%w: no certificate", ErrChainNotAnchored)
	}

	// KeyUsages must be given. Without it Go defaults to
	// ExtKeyUsageServerAuth, and the EFOS issuers carry a restricted
	// extended key usage without serverAuth — the chain would then be
	// rejected with "incompatible key usage", which looks like a broken
	// card but is our own mistake.
	chains, err := card.Verify(x509.VerifyOptions{
		Roots:         t.roots,
		Intermediates: t.intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   t.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChainNotAnchored, err)
	}

	if err := checkSuitability(card); err != nil {
		return nil, err
	}

	// Verify returns the chain leaf first, so the next link is the issuer.
	chain := chains[0]
	if len(chain) < 2 {
		return nil, fmt.Errorf(
			"%w: the card is self-signed and has no issuer", ErrUnsuitableCertificate)
	}

	return chain[1], nil
}

// TrustAnchorContents reports which issuers an anchor trusts.
type TrustAnchorContents struct {
	Roots         []string
	Intermediates []string
}

// Contents reports which issuers the anchor trusts, so that an operator can see
// it without reading the PEM file.
func (t *TrustAnchor) Contents() TrustAnchorContents {
	return TrustAnchorContents{
		Roots:         slices.Clone(t.rootNames),
		Intermediates: slices.Clone(t.issuerNames),
	}
}

// checkSuitability covers what Verify does not.
func checkSuitability(card *x509.Certificate) error {
	if card.IsCA {
		return fmt.Errorf(
			"%w: an issuer certificate must not authenticate a person",
			ErrUnsuitableCertificate)
	}

	if !slices.Contains(allowedSignatureAlgorithms, card.SignatureAlgorithm) {
		return fmt.Errorf("%w: the signature algorithm %v is not allowed",
			ErrUnsuitableCertificate, card.SignatureAlgorithm)
	}

	switch key := card.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits < minimumRSAKeySize {
			return fmt.Errorf("%w: %d-bit rsa key, at least %d is required",
				ErrUnsuitableCertificate, bits, minimumRSAKeySize)
		}
	case *ecdsa.PublicKey:
		// EFOS issues RSA today, but the CP permits ECDSA. P-256 and
		// above are accepted; the curve is carried by the signature
		// algorithm already checked.
	default:
		return fmt.Errorf("%w: the key type %T is not supported",
			ErrUnsuitableCertificate, card.PublicKey)
	}

	return nil
}
