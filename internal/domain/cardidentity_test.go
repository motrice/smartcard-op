// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/domain"
)

// now is the fixed instant the domain tests reckon from. The domain receives
// time as an argument, so no test needs to touch the system clock.
var now = time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)

// validDetails returns an EFOS authentication certificate's details exactly as
// the profile EFOS End Entity Person Certificates rev 1.6 prescribes them.
func validDetails() domain.CertificateDetails {
	return domain.CertificateDetails{
		SubjectSerialNumber:   "195606019577",
		EfosID:                "EFOS-4711",
		GivenName:             "Anna",
		FamilyName:            "Andersson",
		CommonName:            "Anna Andersson",
		Organization:          "Swedish Social Insurance Agency",
		OrganizationNumberRaw: "2021005208",
		PolicyOIDs:            []string{"1.2.752.146.220.3"},
		ExtendedKeyUsage: []string{
			domain.OIDClientAuth,
			domain.OIDSmartcardLogon,
		},
		HasDigitalSignature: true,
		NotBefore:           now.Add(-24 * time.Hour),
		NotAfter:            now.Add(24 * time.Hour),
	}
}

func TestNewCardIdentityAcceptsAValidCard(t *testing.T) {
	t.Parallel()

	identity, err := domain.NewCardIdentity(validDetails(), domain.AssuranceLevel3, now)
	if err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}

	if got := identity.PersonalIdentityNumber().String(); got != "195606019577" {
		t.Errorf("PersonalIdentityNumber() = %q", got)
	}

	if got := identity.EfosID().String(); got != "EFOS-4711" {
		t.Errorf("EfosID() = %q", got)
	}

	if got := identity.Name().GivenName(); got != "Anna" {
		t.Errorf("Name().GivenName() = %q", got)
	}

	if got := identity.AssuranceLevel(); got != domain.AssuranceLevel3 {
		t.Errorf("AssuranceLevel() = %v", got)
	}

	if got := identity.OrganizationNumber().String(); got != "2021005208" {
		t.Errorf("OrganizationNumber() = %q", got)
	}

	if got := identity.Organization(); got != "Swedish Social Insurance Agency" {
		t.Errorf("Organization() = %q", got)
	}
}

func TestNewCardIdentityEnforcesTheDomainRules(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate   func(*domain.CertificateDetails)
		required domain.AssuranceLevel
		wantErr  error
	}{
		"expired certificate": {
			mutate:  func(d *domain.CertificateDetails) { d.NotAfter = now.Add(-time.Second) },
			wantErr: domain.ErrCertificateOutsideValidity,
		},
		"certificate not yet valid": {
			mutate:  func(d *domain.CertificateDetails) { d.NotBefore = now.Add(time.Hour) },
			wantErr: domain.ErrCertificateOutsideValidity,
		},
		"lacks digitalSignature": {
			mutate:  func(d *domain.CertificateDetails) { d.HasDigitalSignature = false },
			wantErr: domain.ErrDisallowedKeyUsage,
		},
		"lacks clientAuth": {
			mutate: func(d *domain.CertificateDetails) {
				d.ExtendedKeyUsage = []string{domain.OIDSmartcardLogon}
			},
			wantErr: domain.ErrDisallowedKeyUsage,
		},
		"lacks smartcardLogon": {
			mutate: func(d *domain.CertificateDetails) {
				d.ExtendedKeyUsage = []string{domain.OIDClientAuth}
			},
			wantErr: domain.ErrDisallowedKeyUsage,
		},
		"assurance level too low": {
			mutate: func(d *domain.CertificateDetails) {
				d.PolicyOIDs = []string{"1.2.752.146.210.2"}
			},
			required: domain.AssuranceLevel3,
			wantErr:  domain.ErrAssuranceLevelTooLow,
		},
		"unknown policy identifier": {
			mutate:  func(d *domain.CertificateDetails) { d.PolicyOIDs = nil },
			wantErr: domain.ErrUnknownAssuranceLevel,
		},
		"malformed identity number": {
			mutate: func(d *domain.CertificateDetails) {
				d.SubjectSerialNumber = "HSA-SE2321000016"
			},
			wantErr: domain.ErrInvalidPersonalIdentityNumber,
		},
		"missing efos identifier": {
			mutate:  func(d *domain.CertificateDetails) { d.EfosID = "" },
			wantErr: domain.ErrInvalidEfosID,
		},
		"no name at all": {
			mutate: func(d *domain.CertificateDetails) {
				d.GivenName, d.FamilyName, d.CommonName = "", "", ""
			},
			wantErr: domain.ErrInvalidName,
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			details := validDetails()
			testCase.mutate(&details)

			required := testCase.required
			if required == domain.AssuranceLevelUnknown {
				required = domain.AssuranceLevel2
			}

			_, err := domain.NewCardIdentity(details, required, now)
			if err == nil {
				t.Fatal("NewCardIdentity returned no error, want one")
			}

			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

// Level 4 must suffice where level 3 is required.
func TestNewCardIdentityAcceptsAHigherAssuranceLevelThanRequired(t *testing.T) {
	t.Parallel()

	details := validDetails()
	details.PolicyOIDs = []string{"1.2.752.146.230.4"}

	identity, err := domain.NewCardIdentity(details, domain.AssuranceLevel3, now)
	if err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}

	if got := identity.AssuranceLevel(); got != domain.AssuranceLevel4 {
		t.Errorf("AssuranceLevel() = %v, want %v", got, domain.AssuranceLevel4)
	}
}

// The organization number is descriptive metadata, not part of the identity.
// An unreadable organizationalUnitName must therefore not deny the login — the
// identity is valid but carries no organization number.
func TestNewCardIdentityDeniesNobodyOverAMalformedOrganizationNumber(t *testing.T) {
	t.Parallel()

	details := validDetails()
	details.OrganizationNumberRaw = "not an organization number"

	identity, err := domain.NewCardIdentity(details, domain.AssuranceLevel3, now)
	if err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}

	if !identity.OrganizationNumber().IsZero() {
		t.Errorf("OrganizationNumber() = %q, want empty", identity.OrganizationNumber())
	}
}

// A certificate with an unknown policy identifier beside a known one must pass,
// and extra unknown extended key usages must not interfere either.
func TestNewCardIdentityToleratesExtraOIDs(t *testing.T) {
	t.Parallel()

	details := validDetails()
	details.PolicyOIDs = append(details.PolicyOIDs, "2.5.29.32.0")
	details.ExtendedKeyUsage = append(details.ExtendedKeyUsage, "1.3.6.1.5.5.7.3.4")

	if _, err := domain.NewCardIdentity(details, domain.AssuranceLevel3, now); err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}
}
