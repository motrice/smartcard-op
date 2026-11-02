// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"

	"github.com/motrice/smartcard-op/internal/adapters/efospki"
	"github.com/motrice/smartcard-op/internal/adapters/revocation"
	"github.com/motrice/smartcard-op/internal/adapters/xfcc"
	"github.com/motrice/smartcard-op/internal/app"
	"github.com/motrice/smartcard-op/internal/domain"
)

// xfccHeader is the header Envoy carries the client certificate in.
const xfccHeader = "x-forwarded-client-cert"

// cardLogin serves the one endpoint behind mTLS.
//
// It lives in the composition root rather than in an adapter because it is
// composition: it joins the Envoy header, the use case and the OpenID Provider,
// and a package that did that would have to import all three layers.
//
// The collaborators are function values rather than interfaces. There is one
// implementation of each, the handler is the only caller, and a test can supply
// a closure in two lines — an interface here would buy nothing but indirection.
type cardLogin struct {
	authenticate func(context.Context, *x509.Certificate) (domain.CardIdentity, error)
	complete     func(requestID string, identity domain.CardIdentity) error
	callback     func(context.Context, string) string
	logger       *slog.Logger
}

func (c *cardLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		pageRequestUnknown.render(w, "")

		return
	}

	certificate, err := xfcc.Parse(r.Header.Values(xfccHeader))
	if err != nil {
		// Reaching the card listener without a certificate means Envoy is
		// misconfigured or something bypassed it. Either way it is an
		// operator's problem, not the user's, and it must be loud.
		c.logger.Error("the card listener was reached without a usable client certificate",
			slog.String("error", err.Error()))
		pageCertificateMissing.render(w, "")

		return
	}

	reference := referenceFor(certificate)

	identity, err := c.authenticate(r.Context(), certificate)
	if err != nil {
		pageFor(err).render(w, reference)

		return
	}

	if err := c.complete(requestID, identity); err != nil {
		pageRequestUnknown.render(w, reference)

		return
	}

	// Hand control back to the OpenID Provider, which issues the
	// authorization code and redirects on to Zitadel.
	http.Redirect(w, r, c.callback(r.Context(), requestID), http.StatusFound)
}

// pageFor maps a denial to what the user is shown.
//
// Each branch is a situation the user can act on differently, which is the
// whole point of not showing one generic failure: the commonest real case is
// picking the signing certificate off a card that holds several, and telling
// someone that is a one-click fix rather than a mystery.
func pageFor(err error) page {
	switch {
	case errors.Is(err, domain.ErrCertificateOutsideValidity):
		return pageCardExpired
	case errors.Is(err, domain.ErrDisallowedKeyUsage):
		return pageWrongCertificate
	case errors.Is(err, domain.ErrAssuranceLevelTooLow):
		return pageAssuranceTooLow
	case errors.Is(err, app.ErrCardRevoked):
		return pageCardRevoked
	case errors.Is(err, app.ErrRevocationStatusUnknown),
		errors.Is(err, revocation.ErrRevocationUnreachable),
		errors.Is(err, revocation.ErrNoRevocationEndpoints):
		return pageRevocationUnavailable
	case errors.Is(err, app.ErrCertificateChain),
		errors.Is(err, efospki.ErrChainNotAnchored),
		errors.Is(err, efospki.ErrUnsuitableCertificate):
		return pageUntrustedIssuer
	case errors.Is(err, app.ErrUnreadableCertificate),
		errors.Is(err, domain.ErrInvalidPersonalIdentityNumber),
		errors.Is(err, domain.ErrInvalidEfosID),
		errors.Is(err, domain.ErrInvalidName),
		errors.Is(err, domain.ErrUnknownAssuranceLevel):
		return pageIdentityMissing
	default:
		return pageCertificateMissing
	}
}

// referenceFor gives the user a short code that joins their screen to the audit
// record. It is a prefix of the certificate fingerprint, which the audit log
// records in full — short enough to read out over the telephone, and it
// discloses nothing about the person.
func referenceFor(certificate *x509.Certificate) string {
	const referenceLength = 12

	full := fingerprintOf(certificate)
	if len(full) < referenceLength {
		return full
	}

	return full[:referenceLength]
}
