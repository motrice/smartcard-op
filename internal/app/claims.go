// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package app

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/motrice/smartcard-op/internal/domain"
)

// ErrInvalidEmailDomain wraps a misconfigured domain for the synthetic email
// addresses.
var ErrInvalidEmailDomain = errors.New("invalid email domain")

// Claim names outside OIDC Core. They follow the Claims and Scopes
// Specification for the Swedish OpenID Connect Profile, which makes the
// identity readable to any relying party that already speaks Swedish eID — and
// future-proofs a connection to Sweden Connect.
const (
	ClaimPersonalIdentityNumber = "https://id.oidc.se/claim/personalIdentityNumber"
	ClaimOrgAffiliation         = "https://id.oidc.se/claim/orgAffiliation"
	// ClaimEfosID is our own: the EFOS portal's identifier has no
	// counterpart in the Swedish profile.
	ClaimEfosID = "efos_id"
)

// Claims are the facts about the user handed to Zitadel.
//
// The first six fields are mandatory in practice, not merely by our own
// preference: Zitadel copies given_name, family_name, email and
// preferred_username unconditionally when creating a brokered user and requires
// at least one character in each (zitadel/zitadel#12265). An empty field yields
// user_creation_failed with no way forward for the user.
type Claims struct {
	Sub               string
	PreferredUsername string
	Name              string
	GivenName         string
	FamilyName        string
	Email             string
	EmailVerified     bool

	ACR                    string
	PersonalIdentityNumber string
	OrgAffiliation         string
	Organization           string
	EfosID                 string
}

// NewClaims translates a card identity into claims.
//
// syntheticEmailDomain is the domain synthetic addresses are placed under when
// the certificate carries none. Choose a domain the agency owns and that has no
// MX record, not .invalid: both pass validation, but a domain of your own
// cannot be registered by anyone else and will not trip later validators.
func NewClaims(identity domain.CardIdentity, syntheticEmailDomain string) (Claims, error) {
	email, verified, err := emailAddress(identity, syntheticEmailDomain)
	if err != nil {
		return Claims{}, err
	}

	claims := Claims{
		// The personal identity number, not the certificate's serial
		// number, is the subject: it is stable when the card is
		// replaced, so a user who lost their card keeps their Zitadel
		// account.
		Sub:               identity.PersonalIdentityNumber().String(),
		PreferredUsername: identity.PersonalIdentityNumber().String(),
		Name:              identity.Name().DisplayName(),
		GivenName:         identity.Name().GivenName(),
		FamilyName:        identity.Name().FamilyName(),
		Email:             email,
		EmailVerified:     verified,

		ACR:                    identity.AssuranceLevel().ACR(),
		PersonalIdentityNumber: identity.PersonalIdentityNumber().String(),
		Organization:           identity.Organization(),
		EfosID:                 identity.EfosID().String(),
	}

	if number := identity.OrganizationNumber(); !number.IsZero() {
		claims.OrgAffiliation = number.String()
	}

	return claims, nil
}

// emailAddress prefers the certificate's own address if it has one, and
// synthesises one otherwise.
//
// The synthetic address is marked verified. That is not a claim that mail was
// confirmed, but that the address is not user-asserted and therefore needs no
// proving — and it stops Zitadel from sending a confirmation code to an address
// that can never receive mail. The consequence is that email-based account
// recovery is disabled for card users, which is deliberate: recovery happens by
// obtaining a new EFOS card.
func emailAddress(identity domain.CardIdentity, domainName string) (string, bool, error) {
	if own := identity.Email(); own != "" {
		if _, err := mail.ParseAddress(own); err == nil {
			return own, false, nil
		}
	}

	if err := checkDomain(domainName); err != nil {
		return "", false, err
	}

	address := fmt.Sprintf("%s@%s", localPart(identity), domainName)
	if _, err := mail.ParseAddress(address); err != nil {
		return "", false, fmt.Errorf(
			"%w: %q does not yield a valid address: %w", ErrInvalidEmailDomain, domainName, err)
	}

	return address, true, nil
}

// localPart builds the address's local part from the EFOS identifier rather
// than from the personal identity number: the address propagates to every
// application behind Zitadel, and the EFOS identifier discloses less about the
// person.
func localPart(identity domain.CardIdentity) string {
	allowed := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return -1
		}
	}

	if part := strings.Map(allowed, identity.EfosID().String()); part != "" {
		return part
	}

	return identity.PersonalIdentityNumber().String()
}

func checkDomain(domainName string) error {
	if strings.TrimSpace(domainName) != domainName || domainName == "" {
		return fmt.Errorf(
			"%w: %q is empty or has surrounding whitespace", ErrInvalidEmailDomain, domainName)
	}

	if strings.ContainsAny(domainName, "@ \t") || !strings.Contains(domainName, ".") {
		return fmt.Errorf("%w: %q is not a domain name", ErrInvalidEmailDomain, domainName)
	}

	return nil
}
