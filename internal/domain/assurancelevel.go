// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"errors"
	"fmt"
)

// ErrUnknownAssuranceLevel wraps every certificate whose assurance level
// cannot be established unambiguously.
var ErrUnknownAssuranceLevel = errors.New("unknown assurance level")

// AssuranceLevel is the level of assurance EFOS issued the card at, as defined
// by the Swedish Agency for Digital Government's trust framework. The level is
// derived solely from the certificate policy identifier — never from the
// issuer's name, which carries no binding meaning.
type AssuranceLevel uint8

const (
	// AssuranceLevelUnknown is the zero value and never satisfies a
	// requirement.
	AssuranceLevelUnknown AssuranceLevel = 0
	AssuranceLevel2       AssuranceLevel = 2
	AssuranceLevel3       AssuranceLevel = 3
	AssuranceLevel4       AssuranceLevel = 4
)

// policyOIDToLevel holds the EFOS certificate policy identifiers for person
// certificates, per EFOS CP section 1.2.
//
// The HSA profile's issuers (1.2.752.146.260.2, .270.3 and .280.4) are
// deliberately left out: they carry an HSA identifier in subject:serialNumber
// rather than a personal identity number, and need their own certificate
// profile before they can be admitted.
var policyOIDToLevel = map[string]AssuranceLevel{
	"1.2.752.146.210.2": AssuranceLevel2,
	"1.2.752.146.220.3": AssuranceLevel3,
	"1.2.752.146.230.4": AssuranceLevel4,
}

// AssuranceLevelFromPolicyOID derives the assurance level from a certificate's
// policy identifiers.
//
// Unknown identifiers are ignored as long as exactly one known identifier is
// present — EFOS may extend the extension without breaking logins — but two
// known identifiers at once are ambiguous and rejected.
func AssuranceLevelFromPolicyOID(oids []string) (AssuranceLevel, error) {
	found := AssuranceLevelUnknown

	for _, oid := range oids {
		level, known := policyOIDToLevel[oid]
		if !known {
			continue
		}

		if found != AssuranceLevelUnknown && found != level {
			return AssuranceLevelUnknown, fmt.Errorf(
				"%w: the certificate carries both level %d and %d",
				ErrUnknownAssuranceLevel, found, level)
		}

		found = level
	}

	if found == AssuranceLevelUnknown {
		return AssuranceLevelUnknown, fmt.Errorf(
			"%w: no known EFOS policy identifier among the %d given",
			ErrUnknownAssuranceLevel, len(oids))
	}

	return found, nil
}

// Satisfies reports whether the level meets a requirement. The zero value
// satisfies nothing.
func (a AssuranceLevel) Satisfies(required AssuranceLevel) bool {
	return a != AssuranceLevelUnknown && a >= required
}

// ACR returns Sweden Connect's identifier for the assurance level, intended as
// the acr claim so that relying parties can read the level in a standardised
// form.
func (a AssuranceLevel) ACR() string {
	if a == AssuranceLevelUnknown {
		return ""
	}

	return fmt.Sprintf("http://id.elegnamnden.se/loa/1.0/loa%d", uint8(a))
}

// String describes the level in logs and error messages.
func (a AssuranceLevel) String() string {
	if a == AssuranceLevelUnknown {
		return "unknown assurance level"
	}

	return fmt.Sprintf("assurance level %d", uint8(a))
}
