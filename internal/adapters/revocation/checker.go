// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package revocation

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrNoRevocationEndpoints means the certificate carries neither an
	// authority information access nor a CRL distribution point, and so
	// cannot be revocation-checked at all.
	ErrNoRevocationEndpoints = errors.New("the certificate carries no revocation endpoints")
	// ErrRevocationUnreachable means neither the responder nor the
	// revocation list could be reached.
	ErrRevocationUnreachable = errors.New("no revocation source could be reached")
)

// maxCacheTime caps how long a valid verdict is cached, regardless of what the
// verdict itself says. EFOS refreshes its responder at least hourly, but a card
// can be revoked in between — the cap bounds how long we might admit someone
// whose card was just revoked.
const maxCacheTime = 10 * time.Minute

// Querier is a revocation source: the responder or a revocation list.
type Querier interface {
	Query(
		ctx context.Context,
		card *x509.Certificate,
		issuer *x509.Certificate,
		address string,
	) (domain.RevocationVerdict, error)
}

// Checker is the revocation policy engine. It satisfies the port the use case
// declares, structurally and without knowing about it.
type Checker struct {
	responder Querier
	lists     Querier
	now       func() time.Time

	mutex sync.Mutex
	cache map[string]cachedVerdict
}

type cachedVerdict struct {
	verdict    domain.RevocationVerdict
	validUntil time.Time
}

// NewChecker assembles the policy engine.
func NewChecker(responder, lists Querier) *Checker {
	return &Checker{
		responder: responder,
		lists:     lists,
		now:       time.Now,
		cache:     make(map[string]cachedVerdict),
	}
}

// Check determines the card's revocation status.
//
// The responder is asked first. An answer from it is final — including "revoked"
// and "unknown". The revocation list is read only when the responder could not
// be reached; otherwise a hostile or broken responder could buy itself a second
// chance by refusing to answer properly.
func (c *Checker) Check(
	ctx context.Context,
	card *x509.Certificate,
	issuer *x509.Certificate,
) (domain.RevocationVerdict, error) {
	key := cacheKey(card, issuer)
	if verdict, present := c.fromCache(key); present {
		return verdict, nil
	}

	if len(card.OCSPServer) == 0 && len(card.CRLDistributionPoints) == 0 {
		return domain.RevocationVerdict{}, ErrNoRevocationEndpoints
	}

	failures := make([]error, 0, 4)

	for _, address := range card.OCSPServer {
		verdict, err := c.responder.Query(ctx, card, issuer, address)
		if err != nil {
			failures = append(failures, fmt.Errorf("ocsp %s: %w", address, err))

			continue
		}

		c.store(key, verdict)

		return verdict, nil
	}

	for _, address := range card.CRLDistributionPoints {
		verdict, err := c.lists.Query(ctx, card, issuer, address)
		if err != nil {
			failures = append(failures, fmt.Errorf("crl %s: %w", address, err))

			continue
		}

		c.store(key, verdict)

		return verdict, nil
	}

	return domain.RevocationVerdict{}, fmt.Errorf(
		"%w: %w", ErrRevocationUnreachable, errors.Join(failures...))
}

func (c *Checker) fromCache(key string) (domain.RevocationVerdict, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	cached, present := c.cache[key]
	if !present || !c.now().Before(cached.validUntil) {
		return domain.RevocationVerdict{}, false
	}

	verdict := cached.verdict
	verdict.FromCache = true

	return verdict, true
}

// store caches only expressly valid verdicts.
//
// A revoked or unknown verdict is never cached. The cache exists to save
// network calls in the normal case, and a revoked card is not the normal case;
// caching it would also hide a later change of mind by EFOS.
func (c *Checker) store(key string, verdict domain.RevocationVerdict) {
	if verdict.Status != domain.RevocationStatusValid {
		return
	}

	validUntil := c.now().Add(maxCacheTime)
	if !verdict.ValidUntil.IsZero() && verdict.ValidUntil.Before(validUntil) {
		validUntil = verdict.ValidUntil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[key] = cachedVerdict{verdict: verdict, validUntil: validUntil}
}

// cacheKey binds the verdict to both the issuer and the card's serial number.
// A serial number is only unique within one issuer, so the issuer must be part
// of the key.
func cacheKey(card, issuer *x509.Certificate) string {
	issuerPart := hex.EncodeToString(issuer.SubjectKeyId)
	if issuerPart == "" {
		issuerPart = issuer.Subject.String()
	}

	return issuerPart + "/" + card.SerialNumber.String()
}
