// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"errors"
	"testing"

	"github.com/motrice/smartcard-op/internal/domain"
)

func TestNewEfosID(t *testing.T) {
	t.Parallel()

	id, err := domain.NewEfosID("  EFOS-1234  ")
	if err != nil {
		t.Fatalf("NewEfosID returned error: %v", err)
	}

	if got := id.String(); got != "EFOS-1234" {
		t.Errorf("String() = %q, want %q", got, "EFOS-1234")
	}

	for _, raw := range []string{"", "   ", "\t\n"} {
		if _, err := domain.NewEfosID(raw); !errors.Is(err, domain.ErrInvalidEfosID) {
			t.Errorf("NewEfosID(%q): error = %v, want ErrInvalidEfosID", raw, err)
		}
	}
}

func TestNewOrganizationNumber(t *testing.T) {
	t.Parallel()

	// 2021005208 is the Swedish Social Insurance Agency's organization
	// number.
	number, err := domain.NewOrganizationNumber("2021005208")
	if err != nil {
		t.Fatalf("NewOrganizationNumber returned error: %v", err)
	}

	if got := number.String(); got != "2021005208" {
		t.Errorf("String() = %q, want %q", got, "2021005208")
	}
}

func TestNewOrganizationNumberRejectsInvalidOnes(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":             "",
		"nine digits":       "202100520",
		"eleven digits":     "20210052081",
		"hyphen":            "202100-5208",
		"letters":           "20210052XX",
		"wrong check digit": "2021005209",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := domain.NewOrganizationNumber(raw)
			if !errors.Is(err, domain.ErrInvalidOrganizationNumber) {
				t.Errorf("error = %v, want ErrInvalidOrganizationNumber", err)
			}
		})
	}
}
