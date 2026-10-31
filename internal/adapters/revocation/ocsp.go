// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package revocation checks whether an EFOS certificate has been revoked.
//
// EFOS CP section 4.9.6 obliges relying parties to check revocation status, and
// this package does so fail-closed: only an express "valid" verdict lets a
// request through. Envoy cannot do the work for us — its client certificate
// support covers only static CRL files, and ocsp_staple concerns the server's
// own certificate.
package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrResponderUnreachable means no valid answer could be obtained. It is
	// the only error permitted to lead on to the CRL fallback.
	ErrResponderUnreachable = errors.New("the revocation responder could not be reached")
	// ErrDisallowedResponderCertificate means the response was signed with a
	// certificate that may not answer for revocation status.
	ErrDisallowedResponderCertificate = errors.New("disallowed responder certificate")
	// ErrStaleResponse means the response was too old or dated in the
	// future.
	ErrStaleResponse = errors.New("the revocation verdict is not current")
)

const (
	// clockSkew is the time difference we tolerate against EFOS clocks.
	clockSkew = 2 * time.Minute
	// maxResponseAge caps how old a response without nextUpdate may be.
	// EFOS refreshes its responder at least hourly, so the cap is generous
	// — but it exists, because x/crypto/ocsp supports no nonce and
	// freshness is therefore the only thing bounding replay of an old
	// "good".
	maxResponseAge = 7 * 24 * time.Hour
	// maxResponseSize stops a responder from feeding us without bound.
	maxResponseSize = 1 << 20
	// requestTimeout caps each OCSP call.
	requestTimeout = 5 * time.Second
	// oidOCSPSigning is id-kp-OCSPSigning.
	oidOCSPSigning = "1.3.6.1.5.5.7.3.9"
)

// OCSP queries the EFOS revocation responder directly.
type OCSP struct {
	client *http.Client
	now    func() time.Time
}

// NewOCSP creates the client. Given no http.Client it uses one of its own with
// a timeout — never http.DefaultClient, which has no timeout and is shared with
// everything else.
func NewOCSP(client *http.Client) *OCSP {
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}

	return &OCSP{client: client, now: time.Now}
}

// Query fetches a revocation verdict for the card from an address in the
// certificate's authority information access extension.
//
// Both ocsp.Revoked and ocsp.Unknown are binding answers and are returned
// without error: they must never lead on to the CRL fallback, since a hostile
// or broken responder could otherwise buy itself a second chance by refusing to
// answer properly.
func (o *OCSP) Query(
	ctx context.Context,
	card *x509.Certificate,
	issuer *x509.Certificate,
	address string,
) (domain.RevocationVerdict, error) {
	// Passing nil as RequestOptions selects SHA-1 for the CertID. That is
	// deliberate: SHA-1 is near-universal in OCSP and many responders
	// reject SHA-256 CertIDs. It is an identifier hash, not a signature —
	// collision resistance is not load-bearing here.
	request, err := ocsp.CreateRequest(card, issuer, nil)
	if err != nil {
		return domain.RevocationVerdict{}, fmt.Errorf("could not build ocsp request: %w", err)
	}

	body, err := o.send(ctx, address, request)
	if err != nil {
		return domain.RevocationVerdict{}, err
	}

	// ParseResponseForCert verifies the signature against the issuer, and
	// that an embedded responder certificate was in turn signed by the
	// issuer.
	response, err := ocsp.ParseResponseForCert(body, card, issuer)
	if err != nil {
		// Both a malformed response and one with a bad signature land
		// here. Both are treated as an unreachable responder, which
		// leads to the CRL fallback. That is safe: the revocation list
		// is verified independently against the issuer, so a hostile
		// responder gains nothing by forcing the fallback.
		return domain.RevocationVerdict{}, fmt.Errorf(
			"%w: the response could not be verified: %w", ErrResponderUnreachable, err)
	}

	if err := o.checkResponderCertificate(response); err != nil {
		return domain.RevocationVerdict{}, err
	}

	if err := o.checkFreshness(response); err != nil {
		return domain.RevocationVerdict{}, err
	}

	return verdictFrom(response), nil
}

func (o *OCSP) send(ctx context.Context, address string, request []byte) ([]byte, error) {
	httpRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, address, bytes.NewReader(request))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponderUnreachable, err)
	}

	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	httpRequest.Header.Set("Accept", "application/ocsp-response")

	response, err := o.client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponderUnreachable, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: answered %s", ErrResponderUnreachable, response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponderUnreachable, err)
	}

	return body, nil
}

// checkResponderCertificate covers the gap golang.org/x/crypto/ocsp leaves.
//
// The library verifies that an embedded responder certificate was signed by the
// issuer, but checks neither its extended key usage nor its validity period.
// Without the extended key usage check, any certificate the EFOS issuer ever
// signed — a stolen card included — could sign revocation verdicts about every
// other card. That is the most serious gap.
func (o *OCSP) checkResponderCertificate(response *ocsp.Response) error {
	if response.Certificate == nil {
		// The response is signed by the issuer itself, which the library
		// has already verified.
		return nil
	}

	if !hasOCSPSigning(response.Certificate) {
		return fmt.Errorf("%w: %q lacks id-kp-OCSPSigning",
			ErrDisallowedResponderCertificate, response.Certificate.Subject.CommonName)
	}

	now := o.now()
	if now.Add(clockSkew).Before(response.Certificate.NotBefore) ||
		now.Add(-clockSkew).After(response.Certificate.NotAfter) {
		return fmt.Errorf("%w: %q is valid %s-%s",
			ErrDisallowedResponderCertificate,
			response.Certificate.Subject.CommonName,
			response.Certificate.NotBefore.Format(time.RFC3339),
			response.Certificate.NotAfter.Format(time.RFC3339))
	}

	// The responder certificate's own revocation status is not checked. That
	// is deliberate and is the norm: id-pkix-ocsp-nocheck exists precisely
	// to say the certificate is short-lived enough not to need checking, and
	// recursing would be an endless problem.

	return nil
}

// hasOCSPSigning looks for id-kp-OCSPSigning in both fields. Go moves known
// OIDs into ExtKeyUsage when parsing, but a certificate may carry it as unknown
// if the parsing went differently.
func hasOCSPSigning(cert *x509.Certificate) bool {
	if slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return true
	}

	return slices.ContainsFunc(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool {
		return oid.String() == oidOCSPSigning
	})
}

// checkFreshness checks currency, which the library does not.
func (o *OCSP) checkFreshness(response *ocsp.Response) error {
	now := o.now()

	if response.ThisUpdate.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: issued %s, which is in the future",
			ErrStaleResponse, response.ThisUpdate.Format(time.RFC3339))
	}

	if !response.NextUpdate.IsZero() {
		if now.Add(-clockSkew).After(response.NextUpdate) {
			return fmt.Errorf("%w: valid until %s",
				ErrStaleResponse, response.NextUpdate.Format(time.RFC3339))
		}

		return nil
	}

	// Without nextUpdate the response has to be judged on its age.
	if now.Sub(response.ThisUpdate) > maxResponseAge {
		return fmt.Errorf("%w: has no nextUpdate and was issued %s",
			ErrStaleResponse, response.ThisUpdate.Format(time.RFC3339))
	}

	return nil
}

func verdictFrom(response *ocsp.Response) domain.RevocationVerdict {
	verdict := domain.RevocationVerdict{
		Method:     domain.RevocationMethodOCSP,
		IssuedAt:   response.ThisUpdate,
		ValidUntil: response.NextUpdate,
	}

	switch response.Status {
	case ocsp.Good:
		verdict.Status = domain.RevocationStatusValid
	case ocsp.Revoked:
		verdict.Status = domain.RevocationStatusRevoked
		verdict.RevokedAt = response.RevokedAt
		verdict.Reason = response.RevocationReason
	default:
		verdict.Status = domain.RevocationStatusUnknown
	}

	return verdict
}
