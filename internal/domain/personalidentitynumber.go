// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ErrInvalidPersonalIdentityNumber wraps every rejected identity number.
var ErrInvalidPersonalIdentityNumber = errors.New("invalid personal identity number")

// personalIdentityNumberLength is the number of digits EFOS writes into
// subject:serialNumber. The EFOS profile prescribes the form YYYYMMDDXXXX
// without a hyphen.
const personalIdentityNumberLength = 12

// coordinationNumberOffset is added to the day of birth in a Swedish
// coordination number ("samordningsnummer").
const coordinationNumberOffset = 60

// PersonalIdentityNumber is a Swedish personal identity number
// ("personnummer") or coordination number ("samordningsnummer") in twelve
// digits. The value object cannot be constructed in an invalid state: every
// instance has passed both the date and the check digit test.
type PersonalIdentityNumber struct {
	digits       string
	birth        time.Time
	coordination bool
}

// NewPersonalIdentityNumber parses and validates an identity number taken
// from a certificate's subject:serialNumber.
func NewPersonalIdentityNumber(raw string) (PersonalIdentityNumber, error) {
	if len(raw) != personalIdentityNumberLength {
		return PersonalIdentityNumber{}, fmt.Errorf(
			"%w: %d characters, want %d",
			ErrInvalidPersonalIdentityNumber, len(raw), personalIdentityNumberLength)
	}

	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return PersonalIdentityNumber{}, fmt.Errorf(
				"%w: character %d is not a digit", ErrInvalidPersonalIdentityNumber, i+1)
		}
	}

	birth, coordination, err := parseDateOfBirth(raw)
	if err != nil {
		return PersonalIdentityNumber{}, err
	}

	// The check digit covers the last ten digits, so without the century.
	if err := verifyLuhn(raw[2:]); err != nil {
		return PersonalIdentityNumber{}, err
	}

	return PersonalIdentityNumber{digits: raw, birth: birth, coordination: coordination}, nil
}

// String returns the number in the same twelve-digit form the certificate
// carried.
func (p PersonalIdentityNumber) String() string { return p.digits }

// DateOfBirth returns the date the number encodes, with a coordination
// number's day offset already subtracted.
func (p PersonalIdentityNumber) DateOfBirth() time.Time { return p.birth }

// IsCoordinationNumber distinguishes a coordination number from a personal
// identity number.
func (p PersonalIdentityNumber) IsCoordinationNumber() bool { return p.coordination }

// IsZero reports whether the value object is the zero value.
func (p PersonalIdentityNumber) IsZero() bool { return p.digits == "" }

func parseDateOfBirth(digits string) (time.Time, bool, error) {
	year, _ := strconv.Atoi(digits[0:4])
	month, _ := strconv.Atoi(digits[4:6])
	day, _ := strconv.Atoi(digits[6:8])

	coordination := day > coordinationNumberOffset
	if coordination {
		day -= coordinationNumberOffset
	}

	if month < 1 || month > 12 {
		return time.Time{}, false, fmt.Errorf(
			"%w: month %d does not exist", ErrInvalidPersonalIdentityNumber, month)
	}

	if day < 1 {
		return time.Time{}, false, fmt.Errorf(
			"%w: day %d does not exist", ErrInvalidPersonalIdentityNumber, day)
	}

	// time.Date normalises overflow, so a round trip exposes dates such as
	// 31 February without us keeping our own table of month lengths.
	date := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if date.Year() != year || date.Month() != time.Month(month) || date.Day() != day {
		return time.Time{}, false, fmt.Errorf(
			"%w: %04d-%02d-%02d does not exist",
			ErrInvalidPersonalIdentityNumber, year, month, day)
	}

	return date, coordination, nil
}

// verifyLuhn checks the trailing check digit using the Luhn algorithm, which
// the Swedish Tax Agency applies to identity numbers. The input is ten digits
// of which the last is the check digit.
func verifyLuhn(tenDigits string) error {
	want := luhnCheckDigit(tenDigits[:len(tenDigits)-1])
	if got := int(tenDigits[len(tenDigits)-1] - '0'); got != want {
		return fmt.Errorf(
			"%w: check digit %d, want %d", ErrInvalidPersonalIdentityNumber, got, want)
	}

	return nil
}
