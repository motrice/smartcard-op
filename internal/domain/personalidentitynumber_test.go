// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"errors"
	"testing"

	"github.com/motrice/smartcard-op/internal/domain"
)

func TestNewPersonalIdentityNumberAcceptsValidNumbers(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"191212121212",
		"195606019577",
		"201701102384",
		"199009264541",
	} {
		number, err := domain.NewPersonalIdentityNumber(raw)
		if err != nil {
			t.Fatalf("NewPersonalIdentityNumber(%q) returned error: %v", raw, err)
		}

		if got := number.String(); got != raw {
			t.Errorf("String() = %q, want %q", got, raw)
		}

		if number.IsCoordinationNumber() {
			t.Errorf("%q was flagged as a coordination number", raw)
		}
	}
}

func TestNewPersonalIdentityNumberAcceptsCoordinationNumbers(t *testing.T) {
	t.Parallel()

	// A coordination number adds 60 to the day of birth, so 1956-06-01
	// becomes day 61.
	const coordination = "195606619574"

	number, err := domain.NewPersonalIdentityNumber(coordination)
	if err != nil {
		t.Fatalf("NewPersonalIdentityNumber(%q) returned error: %v", coordination, err)
	}

	if !number.IsCoordinationNumber() {
		t.Error("IsCoordinationNumber() = false, want true")
	}
}

// Every date case below carries a correct Luhn check digit, so it can only be
// rejected by the date check. Otherwise the check digit test would have masked
// a missing date test.
func TestNewPersonalIdentityNumberRejectsInvalidNumbers(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":                   "",
		"ten digits":              "5606019577",
		"eleven digits":           "19560601957",
		"thirteen digits":         "1956060195771",
		"hyphen":                  "19560601-9577",
		"letters":                 "19560601957X",
		"wrong check digit":       "195606019578",
		"invalid month":           "195613011237",
		"invalid day":             "195606321239",
		"day zero":                "195606001237",
		"leap day in common year": "195702291237",
		"surrounding whitespace":  " 195606019577 ",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := domain.NewPersonalIdentityNumber(raw)
			if err == nil {
				t.Fatalf("NewPersonalIdentityNumber(%q) returned no error, want one", raw)
			}

			if !errors.Is(err, domain.ErrInvalidPersonalIdentityNumber) {
				t.Errorf("error = %v, want ErrInvalidPersonalIdentityNumber", err)
			}
		})
	}
}
