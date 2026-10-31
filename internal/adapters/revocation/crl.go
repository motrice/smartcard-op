// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package revocation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrUntrustedCRL means the list's signature cannot be tied to the
	// issuer.
	ErrUntrustedCRL = errors.New("the revocation list cannot be verified")
	// ErrStaleCRL means the list's validity has lapsed by more than the
	// staleness budget.
	ErrStaleCRL = errors.New("the revocation list is stale")
)

const (
	// maxListSize caps a fetched revocation list. EFOS lists are small, but
	// the cap stops a misdirected address from exhausting memory.
	maxListSize = 32 << 20
	// listTimeout caps each fetch. More generous than the OCSP one, since a
	// revocation list is larger.
	listTimeout = 15 * time.Second
)

// CRL reads EFOS revocation lists. It is the fallback when the responder cannot
// be reached — never when the responder has given a binding answer.
type CRL struct {
	client       *http.Client
	maxStaleness time.Duration
	now          func() time.Time

	mutex sync.Mutex
	cache map[string]*cachedList
}

type cachedList struct {
	list      *x509.RevocationList
	fetchedAt time.Time
}

// NewCRL creates the reader.
//
// maxStaleness is how long past the list's nextUpdate it is still accepted.
// Zero means no tolerance at all, which is the safe default: an operator can
// widen the window during a prolonged EFOS outage, but only expressly and
// therefore reviewably. The value should never be set below the EFOS issuance
// interval.
func NewCRL(client *http.Client, maxStaleness time.Duration) *CRL {
	if client == nil {
		client = &http.Client{Timeout: listTimeout}
	}

	return &CRL{
		client:       client,
		maxStaleness: maxStaleness,
		now:          time.Now,
		cache:        make(map[string]*cachedList),
	}
}

// Query determines the card's revocation status against a revocation list
// fetched from the address in the certificate's CRL distribution point.
func (c *CRL) Query(
	ctx context.Context,
	card *x509.Certificate,
	issuer *x509.Certificate,
	address string,
) (domain.RevocationVerdict, error) {
	list, fromCache, err := c.fetchList(ctx, address, issuer)
	if err != nil {
		return domain.RevocationVerdict{}, err
	}

	if err := c.checkCurrency(list); err != nil {
		return domain.RevocationVerdict{}, err
	}

	verdict := domain.RevocationVerdict{
		Status:     domain.RevocationStatusValid,
		Method:     domain.RevocationMethodCRL,
		IssuedAt:   list.ThisUpdate,
		ValidUntil: list.NextUpdate,
		FromCache:  fromCache,
	}

	// RevokedCertificateEntries, not the deprecated RevokedCertificates.
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(card.SerialNumber) != 0 {
			continue
		}

		verdict.Status = domain.RevocationStatusRevoked
		verdict.RevokedAt = entry.RevocationTime
		verdict.Reason = entry.ReasonCode

		return verdict, nil
	}

	return verdict, nil
}

func (c *CRL) fetchList(
	ctx context.Context,
	address string,
	issuer *x509.Certificate,
) (*x509.RevocationList, bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// The cache holds for as long as the list itself is valid. Otherwise the
	// list would be fetched on every login, and EFOS lists are not small.
	if cached, present := c.cache[address]; present && c.now().Before(cached.list.NextUpdate) {
		return cached.list, true, nil
	}

	der, err := c.load(ctx, address)
	if err != nil {
		return nil, false, err
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, false, fmt.Errorf(
			"%w: the list could not be parsed: %w", ErrResponderUnreachable, err)
	}

	// The signature must be tied to the issuer before the list may mean
	// anything. Without that check, anyone able to answer on the CRL address
	// could serve an empty list and thereby un-revoke every stolen card.
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrUntrustedCRL, err)
	}

	c.cache[address] = &cachedList{list: list, fetchedAt: c.now()}

	return list, false, nil
}

func (c *CRL) load(ctx context.Context, address string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponderUnreachable, err)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponderUnreachable, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: answered %s", ErrResponderUnreachable, response.Status)
	}

	return io.ReadAll(io.LimitReader(response.Body, maxListSize))
}

func (c *CRL) checkCurrency(list *x509.RevocationList) error {
	now := c.now()

	if list.ThisUpdate.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: issued %s, which is in the future",
			ErrStaleCRL, list.ThisUpdate.Format(time.RFC3339))
	}

	if list.NextUpdate.IsZero() {
		return fmt.Errorf("%w: has no nextUpdate", ErrStaleCRL)
	}

	limit := list.NextUpdate.Add(c.maxStaleness)
	if now.Add(-clockSkew).After(limit) {
		return fmt.Errorf("%w: was valid until %s, the budget allows %s",
			ErrStaleCRL, list.NextUpdate.Format(time.RFC3339), c.maxStaleness)
	}

	return nil
}
