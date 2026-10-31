// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package app

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrCertificateChain wraps certificates that cannot be tied to the
	// trust anchor.
	ErrCertificateChain = errors.New("the certificate cannot be tied to a trusted issuer")
	// ErrUnreadableCertificate wraps certificates whose DN cannot be read.
	ErrUnreadableCertificate = errors.New("the certificate's details cannot be read")
	// ErrCardRevoked wraps revoked certificates.
	ErrCardRevoked = errors.New("the card is revoked")
	// ErrRevocationStatusUnknown wraps missing revocation verdicts. It is
	// distinct from ErrCardRevoked because it is an operational fault that
	// should raise an alert, not an expected denial.
	ErrRevocationStatusUnknown = errors.New("the card's revocation status could not be established")
)

// The ports this use case needs. They are deliberately small and declared here,
// next to the code that uses them: adapters satisfy them structurally and need
// not know this package exists.
type (
	// TrustAnchor verifies the certificate chain against the trusted EFOS
	// issuers and returns the issuer that signed the card. The issuer is
	// needed in order to ask the responder about that specific certificate.
	TrustAnchor interface {
		Verify(leaf *x509.Certificate) (issuer *x509.Certificate, err error)
	}

	// CertificateReader translates a certificate into the plain values the
	// domain tests its rules against.
	CertificateReader interface {
		Read(leaf *x509.Certificate) (domain.CertificateDetails, error)
	}

	// RevocationChecker asks EFOS whether the certificate has been revoked.
	// How the question is put — OCSP, CRL, cache — is the adapter's
	// business; the use case only cares about the verdict.
	RevocationChecker interface {
		Check(
			ctx context.Context,
			leaf *x509.Certificate,
			issuer *x509.Certificate,
		) (domain.RevocationVerdict, error)
	}

	// Clock returns the current time, so that time-dependent rules can be
	// tested without waiting.
	Clock interface {
		Now() time.Time
	}

	// AuditLog receives one event per authentication attempt.
	AuditLog interface {
		Write(event AuditEvent)
	}
)

// AuditEvent is one record in the audit log. Exactly one is written per
// attempt, whatever the outcome.
type AuditEvent struct {
	Granted bool
	// Reason is a short, stable code — not an error message. It exists to
	// be counted and alerted on.
	Reason string
	// Fingerprint is SHA-256 over the certificate's DER, hex encoded. It is
	// the correlation key: unique per card, and it discloses nothing about
	// the person.
	Fingerprint string
	// CertificateSerialNumber is the certificate's own serial number, not
	// the identity number in its subject.
	CertificateSerialNumber string
	Issuer                  string
	// PersonalIdentityNumber is passed through as it is. Masking or hashing
	// is the audit log's own decision, since retention and access are
	// governed there.
	PersonalIdentityNumber string
	AssuranceLevel         domain.AssuranceLevel
	RevocationVerdict      domain.RevocationVerdict
	Duration               time.Duration
}

// Dependencies is what Authenticator needs in order to do its work.
type Dependencies struct {
	TrustAnchor       TrustAnchor
	CertificateReader CertificateReader
	RevocationChecker RevocationChecker
	AuditLog          AuditLog
	Clock             Clock
	// MinimumAssuranceLevel is the lowest assurance level accepted.
	MinimumAssuranceLevel domain.AssuranceLevel
}

// Authenticator is the use case: from a client certificate to a card identity,
// or a denial.
type Authenticator struct {
	deps Dependencies
}

// NewAuthenticator assembles the use case.
func NewAuthenticator(deps Dependencies) *Authenticator {
	return &Authenticator{deps: deps}
}

// Authenticate tests a client certificate and returns the card identity it
// attests.
//
// The order is deliberate: chain, details and domain rules first, and the
// revocation check last. Whatever can be decided locally is decided locally —
// partly because the network call is pointless for a card that will not do
// anyway, and partly because a responder that is down must not hide the actual
// fault from the user.
func (a *Authenticator) Authenticate(
	ctx context.Context,
	leaf *x509.Certificate,
) (domain.CardIdentity, error) {
	start := a.deps.Clock.Now()
	event := AuditEvent{
		Fingerprint:             fingerprint(leaf),
		CertificateSerialNumber: serialNumber(leaf),
	}

	// The audit record is written in a defer, so that no early return can
	// leave an attempt without a trace.
	defer func() {
		event.Duration = a.deps.Clock.Now().Sub(start)
		a.deps.AuditLog.Write(event)
	}()

	identity, verdict, err := a.evaluate(ctx, leaf, &event)
	event.RevocationVerdict = verdict

	if err != nil {
		if event.Reason == "" {
			event.Reason = "unknown_error"
		}

		return domain.CardIdentity{}, err
	}

	event.Granted = true
	event.Reason = "granted"
	event.PersonalIdentityNumber = identity.PersonalIdentityNumber().String()
	event.AssuranceLevel = identity.AssuranceLevel()

	return identity, nil
}

func (a *Authenticator) evaluate(
	ctx context.Context,
	leaf *x509.Certificate,
	event *AuditEvent,
) (domain.CardIdentity, domain.RevocationVerdict, error) {
	issuer, err := a.deps.TrustAnchor.Verify(leaf)
	if err != nil {
		event.Reason = "certificate_chain"

		return domain.CardIdentity{}, domain.RevocationVerdict{},
			fmt.Errorf("%w: %w", ErrCertificateChain, err)
	}

	event.Issuer = issuerName(issuer)

	details, err := a.deps.CertificateReader.Read(leaf)
	if err != nil {
		event.Reason = "unreadable_certificate"

		return domain.CardIdentity{}, domain.RevocationVerdict{},
			fmt.Errorf("%w: %w", ErrUnreadableCertificate, err)
	}

	identity, err := domain.NewCardIdentity(
		details, a.deps.MinimumAssuranceLevel, a.deps.Clock.Now())
	if err != nil {
		event.Reason = domainReason(err)

		return domain.CardIdentity{}, domain.RevocationVerdict{}, err
	}

	event.PersonalIdentityNumber = identity.PersonalIdentityNumber().String()
	event.AssuranceLevel = identity.AssuranceLevel()

	verdict, err := a.deps.RevocationChecker.Check(ctx, leaf, issuer)
	if err != nil {
		event.Reason = "revocation_status_unknown"

		return domain.CardIdentity{}, verdict,
			fmt.Errorf("%w: %w", ErrRevocationStatusUnknown, err)
	}

	switch {
	case verdict.Status == domain.RevocationStatusRevoked:
		event.Reason = "revoked"

		return domain.CardIdentity{}, verdict, fmt.Errorf(
			"%w: revoked %s according to %s",
			ErrCardRevoked, verdict.RevokedAt.Format(time.RFC3339), verdict.Method)
	case !verdict.PermitsLogin():
		event.Reason = "revocation_status_unknown"

		return domain.CardIdentity{}, verdict, fmt.Errorf(
			"%w: the verdict was %v", ErrRevocationStatusUnknown, verdict.Status)
	}

	return identity, verdict, nil
}

// domainReason translates a domain error into a stable reason code for the
// audit log and the metrics.
func domainReason(err error) string {
	switch {
	case errors.Is(err, domain.ErrCertificateOutsideValidity):
		return "certificate_outside_validity"
	case errors.Is(err, domain.ErrDisallowedKeyUsage):
		return "disallowed_key_usage"
	case errors.Is(err, domain.ErrAssuranceLevelTooLow):
		return "assurance_level_too_low"
	case errors.Is(err, domain.ErrUnknownAssuranceLevel):
		return "unknown_assurance_level"
	case errors.Is(err, domain.ErrInvalidPersonalIdentityNumber):
		return "invalid_personal_identity_number"
	case errors.Is(err, domain.ErrInvalidEfosID):
		return "missing_efos_id"
	case errors.Is(err, domain.ErrInvalidName):
		return "missing_name"
	default:
		return "domain_rule"
	}
}

func fingerprint(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}

	sum := sha256.Sum256(leaf.Raw)

	return hex.EncodeToString(sum[:])
}

func serialNumber(leaf *x509.Certificate) string {
	if leaf == nil || leaf.SerialNumber == nil {
		return ""
	}

	return leaf.SerialNumber.String()
}

func issuerName(issuer *x509.Certificate) string {
	if issuer == nil {
		return ""
	}

	return issuer.Subject.String()
}
