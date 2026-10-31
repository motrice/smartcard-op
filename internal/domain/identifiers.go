// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidEfosID wraps certificates without a usable EFOS identifier.
	ErrInvalidEfosID = errors.New("invalid EFOS identifier")
	// ErrInvalidOrganizationNumber wraps certificates whose
	// organizationalUnitName is not an organization number.
	ErrInvalidOrganizationNumber = errors.New("invalid organization number")
)

// organizationNumberLength is the number of digits EFOS writes into
// organizationalUnitName, per the profile's format XXXXXXXXXX.
const organizationNumberLength = 10

// EfosID is the person's identity in the EFOS portal, carried in the
// certificate's subject:title attribute.
type EfosID struct {
	value string
}

// NewEfosID validates an EFOS identifier taken from subject:title.
func NewEfosID(raw string) (EfosID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return EfosID{}, fmt.Errorf("%w: subject:title is empty", ErrInvalidEfosID)
	}

	return EfosID{value: raw}, nil
}

// String returns the identifier as the certificate carried it.
func (e EfosID) String() string { return e.value }

// IsZero reports whether the value object is the zero value.
func (e EfosID) IsZero() bool { return e.value == "" }

// OrganizationNumber is the employing organization's Swedish organization
// number, carried in the certificate's organizationalUnitName attribute.
type OrganizationNumber struct {
	digits string
}

// NewOrganizationNumber validates a ten-digit organization number.
func NewOrganizationNumber(raw string) (OrganizationNumber, error) {
	raw = strings.TrimSpace(raw)

	if len(raw) != organizationNumberLength || !isAllDigits(raw) {
		return OrganizationNumber{}, fmt.Errorf(
			"%w: %q is not ten digits", ErrInvalidOrganizationNumber, raw)
	}

	want := luhnCheckDigit(raw[:organizationNumberLength-1])
	if got := int(raw[organizationNumberLength-1] - '0'); got != want {
		return OrganizationNumber{}, fmt.Errorf(
			"%w: check digit %d, want %d", ErrInvalidOrganizationNumber, got, want)
	}

	return OrganizationNumber{digits: raw}, nil
}

// String returns the number as ten digits without a hyphen.
func (o OrganizationNumber) String() string { return o.digits }

// IsZero reports whether the value object is the zero value.
func (o OrganizationNumber) IsZero() bool { return o.digits == "" }
