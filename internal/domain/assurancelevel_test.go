// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"errors"
	"testing"

	"github.com/motrice/smartcard-op/internal/domain"
)

func TestAssuranceLevelFromPolicyOIDDerivesTheLevel(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		oid  string
		want domain.AssuranceLevel
	}{
		"Person 2 CA": {"1.2.752.146.210.2", domain.AssuranceLevel2},
		"Person 3 CA": {"1.2.752.146.220.3", domain.AssuranceLevel3},
		"Person 4 CA": {"1.2.752.146.230.4", domain.AssuranceLevel4},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			level, err := domain.AssuranceLevelFromPolicyOID([]string{c.oid})
			if err != nil {
				t.Fatalf("AssuranceLevelFromPolicyOID(%q) returned error: %v", c.oid, err)
			}

			if level != c.want {
				t.Errorf("level = %v, want %v", level, c.want)
			}
		})
	}
}

func TestAssuranceLevelFromPolicyOIDRejectsAmbiguousCases(t *testing.T) {
	t.Parallel()

	cases := map[string][]string{
		"no oid at all": {},
		"unknown oid":   {"1.2.752.146.999.9"},
		"empty string":  {""},
		"two efos oids": {"1.2.752.146.220.3", "1.2.752.146.230.4"},
		"hsa profile":   {"1.2.752.146.270.3"},
	}

	for name, oids := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := domain.AssuranceLevelFromPolicyOID(oids)
			if err == nil {
				t.Fatalf("AssuranceLevelFromPolicyOID(%v) returned no error, want one", oids)
			}

			if !errors.Is(err, domain.ErrUnknownAssuranceLevel) {
				t.Errorf("error = %v, want ErrUnknownAssuranceLevel", err)
			}
		})
	}
}

// An unknown oid alongside a known one must not be rejected: EFOS may add
// policy identifiers without logins ceasing to work.
func TestAssuranceLevelFromPolicyOIDToleratesUnknownOIDsBesideAKnownOne(t *testing.T) {
	t.Parallel()

	level, err := domain.AssuranceLevelFromPolicyOID(
		[]string{"2.5.29.32.0", "1.2.752.146.220.3"})
	if err != nil {
		t.Fatalf("returned error: %v", err)
	}

	if level != domain.AssuranceLevel3 {
		t.Errorf("level = %v, want %v", level, domain.AssuranceLevel3)
	}
}

func TestAssuranceLevelSatisfies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		have     domain.AssuranceLevel
		required domain.AssuranceLevel
		want     bool
	}{
		{"level 3 satisfies 3", domain.AssuranceLevel3, domain.AssuranceLevel3, true},
		{"level 4 satisfies 3", domain.AssuranceLevel4, domain.AssuranceLevel3, true},
		{"level 2 does not satisfy 3", domain.AssuranceLevel2, domain.AssuranceLevel3, false},
		{"level 2 satisfies 2", domain.AssuranceLevel2, domain.AssuranceLevel2, true},
		{"level 3 does not satisfy 4", domain.AssuranceLevel3, domain.AssuranceLevel4, false},
		{"unknown satisfies nothing", domain.AssuranceLevelUnknown, domain.AssuranceLevel2, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got := c.have.Satisfies(c.required); got != c.want {
				t.Errorf("%v.Satisfies(%v) = %t, want %t", c.have, c.required, got, c.want)
			}
		})
	}
}

func TestAssuranceLevelACRGivesSwedenConnectIdentifiers(t *testing.T) {
	t.Parallel()

	want := map[domain.AssuranceLevel]string{
		domain.AssuranceLevel2: "http://id.elegnamnden.se/loa/1.0/loa2",
		domain.AssuranceLevel3: "http://id.elegnamnden.se/loa/1.0/loa3",
		domain.AssuranceLevel4: "http://id.elegnamnden.se/loa/1.0/loa4",
	}

	for level, acr := range want {
		if got := level.ACR(); got != acr {
			t.Errorf("%v.ACR() = %q, want %q", level, got, acr)
		}
	}
}
