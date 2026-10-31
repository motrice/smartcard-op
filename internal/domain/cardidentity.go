// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrCertificateOutsideValidity wraps certificates that have expired or
	// have not yet come into force.
	ErrCertificateOutsideValidity = errors.New("the certificate is outside its validity period")
	// ErrDisallowedKeyUsage wraps certificates whose keyUsage or
	// extendedKeyUsage does not permit login. The most common real case is
	// that the user picked the card's signing or encryption certificate
	// rather than the authentication certificate.
	ErrDisallowedKeyUsage = errors.New("the certificate may not be used for login")
	// ErrAssuranceLevelTooLow wraps cards whose assurance level does not
	// meet the requirement.
	ErrAssuranceLevelTooLow = errors.New("the card's assurance level is insufficient")
)

// CardIdentity is the identity an EFOS card attests. The aggregate can only be
// constructed through NewCardIdentity, which enforces every domain rule —
// there is no path to a CardIdentity that violates them.
type CardIdentity struct {
	personalIdentityNumber PersonalIdentityNumber
	efosID                 EfosID
	name                   Name
	organization           string
	organizationNumber     OrganizationNumber
	assuranceLevel         AssuranceLevel
	email                  string
}

// NewCardIdentity tests a certificate's details against the domain rules and
// forms the identity. required is the lowest assurance level accepted and now
// is the instant validity is judged against.
//
// The rules are checked in the order that yields the most useful error first:
// validity and key usage are things the user can act on themselves (fetch a
// new card, pick the right certificate), whereas a malformed DN is a
// certificate profile anomaly for someone else to look into.
func NewCardIdentity(
	details CertificateDetails,
	required AssuranceLevel,
	now time.Time,
) (CardIdentity, error) {
	if err := checkValidity(details, now); err != nil {
		return CardIdentity{}, err
	}

	if err := checkKeyUsage(details); err != nil {
		return CardIdentity{}, err
	}

	assuranceLevel, err := AssuranceLevelFromPolicyOID(details.PolicyOIDs)
	if err != nil {
		return CardIdentity{}, err
	}

	if !assuranceLevel.Satisfies(required) {
		return CardIdentity{}, fmt.Errorf(
			"%w: the card has %v, at least %v is required",
			ErrAssuranceLevelTooLow, assuranceLevel, required)
	}

	personalIdentityNumber, err := NewPersonalIdentityNumber(details.SubjectSerialNumber)
	if err != nil {
		return CardIdentity{}, fmt.Errorf("subject:serialNumber: %w", err)
	}

	efosID, err := NewEfosID(details.EfosID)
	if err != nil {
		return CardIdentity{}, fmt.Errorf("subject:title: %w", err)
	}

	name, err := NewName(details.GivenName, details.FamilyName, details.CommonName)
	if err != nil {
		return CardIdentity{}, err
	}

	// The organization number is descriptive metadata, not part of the
	// identity. An unreadable organizationalUnitName must therefore not
	// deny the login — the identity is formed without it, and whoever wants
	// to know whether that happened can see the field is empty.
	organizationNumber, err := NewOrganizationNumber(details.OrganizationNumberRaw)
	if err != nil {
		organizationNumber = OrganizationNumber{}
	}

	return CardIdentity{
		personalIdentityNumber: personalIdentityNumber,
		efosID:                 efosID,
		name:                   name,
		organization:           details.Organization,
		organizationNumber:     organizationNumber,
		assuranceLevel:         assuranceLevel,
		email:                  strings.TrimSpace(details.Email),
	}, nil
}

func checkValidity(details CertificateDetails, now time.Time) error {
	if now.Before(details.NotBefore) {
		return fmt.Errorf("%w: not valid until %s",
			ErrCertificateOutsideValidity, details.NotBefore.Format(time.RFC3339))
	}

	if now.After(details.NotAfter) {
		return fmt.Errorf("%w: valid until %s",
			ErrCertificateOutsideValidity, details.NotAfter.Format(time.RFC3339))
	}

	return nil
}

func checkKeyUsage(details CertificateDetails) error {
	if !details.HasDigitalSignature {
		return fmt.Errorf("%w: keyUsage lacks digitalSignature", ErrDisallowedKeyUsage)
	}

	// The EFOS profile requires both. Requiring both is also what
	// distinguishes the authentication certificate from the card's other
	// certificates.
	for _, oid := range []string{OIDClientAuth, OIDSmartcardLogon} {
		if !details.hasExtendedKeyUsage(oid) {
			return fmt.Errorf("%w: extendedKeyUsage lacks %s", ErrDisallowedKeyUsage, oid)
		}
	}

	return nil
}

// PersonalIdentityNumber returns the identity number the certificate attests.
func (c CardIdentity) PersonalIdentityNumber() PersonalIdentityNumber {
	return c.personalIdentityNumber
}

// EfosID returns the person's identity in the EFOS portal.
func (c CardIdentity) EfosID() EfosID { return c.efosID }

// Name returns the person's name, with all three parts guaranteed non-empty.
func (c CardIdentity) Name() Name { return c.name }

// Organization returns the employing organization's legal name.
func (c CardIdentity) Organization() string { return c.organization }

// OrganizationNumber returns the organization number, or the zero value if the
// certificate carried no readable one.
func (c CardIdentity) OrganizationNumber() OrganizationNumber {
	return c.organizationNumber
}

// AssuranceLevel returns the level the card was issued at.
func (c CardIdentity) AssuranceLevel() AssuranceLevel { return c.assuranceLevel }

// Email returns the address the certificate carried, or the empty string —
// which is the normal case, since the EFOS profile no longer contains one.
func (c CardIdentity) Email() string { return c.email }
