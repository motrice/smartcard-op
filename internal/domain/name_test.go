// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"errors"
	"testing"

	"github.com/motrice/smartcard-op/internal/domain"
)

func TestNewNamePreservesAllThreeParts(t *testing.T) {
	t.Parallel()

	name, err := domain.NewName("Anna", "Andersson", "Anna Andersson")
	if err != nil {
		t.Fatalf("NewName returned error: %v", err)
	}

	if got := name.GivenName(); got != "Anna" {
		t.Errorf("GivenName() = %q, want %q", got, "Anna")
	}

	if got := name.FamilyName(); got != "Andersson" {
		t.Errorf("FamilyName() = %q, want %q", got, "Andersson")
	}

	if got := name.DisplayName(); got != "Anna Andersson" {
		t.Errorf("DisplayName() = %q, want %q", got, "Anna Andersson")
	}
}

// The EFOS profile allows an empty givenName when the person has no marked
// first name. Zitadel refuses to create a user without given_name and
// family_name (zitadel/zitadel#12265), so the value object guarantees that no
// part is empty.
func TestNewNameFallsBackToTheDisplayName(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		givenName, familyName, displayName string
		wantGiven, wantFamily, wantDisplay string
	}{
		"empty given name": {
			"", "Andersson", "Anna Andersson",
			"Anna Andersson", "Andersson", "Anna Andersson",
		},
		"empty family name": {
			"Anna", "", "Anna Andersson",
			"Anna", "Anna Andersson", "Anna Andersson",
		},
		"empty display name is assembled": {
			"Anna", "Andersson", "",
			"Anna", "Andersson", "Anna Andersson",
		},
		"display name only": {
			"", "", "Anna Andersson",
			"Anna Andersson", "Anna Andersson", "Anna Andersson",
		},
		"family name only": {
			"", "Andersson", "",
			"Andersson", "Andersson", "Andersson",
		},
		"whitespace is trimmed": {
			"  Anna  ", " Andersson ", "  ",
			"Anna", "Andersson", "Anna Andersson",
		},
	}

	for description, testCase := range cases {
		t.Run(description, func(t *testing.T) {
			t.Parallel()

			name, err := domain.NewName(testCase.givenName, testCase.familyName, testCase.displayName)
			if err != nil {
				t.Fatalf("NewName returned error: %v", err)
			}

			if got := name.GivenName(); got != testCase.wantGiven {
				t.Errorf("GivenName() = %q, want %q", got, testCase.wantGiven)
			}

			if got := name.FamilyName(); got != testCase.wantFamily {
				t.Errorf("FamilyName() = %q, want %q", got, testCase.wantFamily)
			}

			if got := name.DisplayName(); got != testCase.wantDisplay {
				t.Errorf("DisplayName() = %q, want %q", got, testCase.wantDisplay)
			}
		})
	}
}

func TestNewNameRejectsAnEntirelyEmptyName(t *testing.T) {
	t.Parallel()

	_, err := domain.NewName("  ", "", "\t")
	if err == nil {
		t.Fatal("NewName with only whitespace returned no error, want one")
	}

	if !errors.Is(err, domain.ErrInvalidName) {
		t.Errorf("error = %v, want ErrInvalidName", err)
	}
}
