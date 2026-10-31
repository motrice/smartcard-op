// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package app_test

import (
	"errors"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/app"
	"github.com/motrice/smartcard-op/internal/domain"
)

var now = time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)

const emailDomain = "card-noreply.example.se"

func details() domain.CertificateDetails {
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

func identity(t *testing.T, d domain.CertificateDetails) domain.CardIdentity {
	t.Helper()

	id, err := domain.NewCardIdentity(d, domain.AssuranceLevel2, now)
	if err != nil {
		t.Fatalf("NewCardIdentity returned error: %v", err)
	}

	return id
}

func TestNewClaimsMapsTheWholeIdentity(t *testing.T) {
	t.Parallel()

	claims, err := app.NewClaims(identity(t, details()), emailDomain)
	if err != nil {
		t.Fatalf("NewClaims returned error: %v", err)
	}

	got := map[string]string{
		"sub":                claims.Sub,
		"preferred_username": claims.PreferredUsername,
		"name":               claims.Name,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
	}
	want := map[string]string{
		"sub":                "195606019577",
		"preferred_username": "195606019577",
		"name":               "Anna Andersson",
		"given_name":         "Anna",
		"family_name":        "Andersson",
	}

	for field, value := range got {
		if value != want[field] {
			t.Errorf("%s = %q, want %q", field, value, want[field])
		}
	}

	if claims.PersonalIdentityNumber != "195606019577" {
		t.Errorf("PersonalIdentityNumber = %q", claims.PersonalIdentityNumber)
	}

	if claims.OrgAffiliation != "2021005208" {
		t.Errorf("OrgAffiliation = %q", claims.OrgAffiliation)
	}

	if claims.ACR != "http://id.elegnamnden.se/loa/1.0/loa3" {
		t.Errorf("ACR = %q", claims.ACR)
	}

	if claims.EfosID != "EFOS-4711" {
		t.Errorf("EfosID = %q", claims.EfosID)
	}
}

// Zitadel copies given_name, family_name, email and preferred_username
// unconditionally when creating a brokered user, and its proto validation
// requires at least one character in each (zitadel/zitadel#12265). If any of
// them is empty the login fails with user_creation_failed and the user has no
// way forward. This test is the guard against that class of fault.
func TestNewClaimsFillsEveryFieldZitadelRequires(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*domain.CertificateDetails){
		"complete certificate": func(*domain.CertificateDetails) {},
		"without given name":   func(d *domain.CertificateDetails) { d.GivenName = "" },
		"without family name":  func(d *domain.CertificateDetails) { d.FamilyName = "" },
		"without common name":  func(d *domain.CertificateDetails) { d.CommonName = "" },
		"common name only":     func(d *domain.CertificateDetails) { d.GivenName, d.FamilyName = "", "" },
		"without org number":   func(d *domain.CertificateDetails) { d.OrganizationNumberRaw = "" },
		"without organization": func(d *domain.CertificateDetails) { d.Organization = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := details()
			mutate(&d)

			claims, err := app.NewClaims(identity(t, d), emailDomain)
			if err != nil {
				t.Fatalf("NewClaims returned error: %v", err)
			}

			mandatory := map[string]string{
				"sub":                claims.Sub,
				"preferred_username": claims.PreferredUsername,
				"name":               claims.Name,
				"given_name":         claims.GivenName,
				"family_name":        claims.FamilyName,
				"email":              claims.Email,
			}
			for field, value := range mandatory {
				if strings.TrimSpace(value) == "" {
					t.Errorf("%s is empty; Zitadel refuses to create the user", field)
				}
			}
		})
	}
}

// The EFOS profile dropped the email field in rev 1.5, so the address has to be
// synthesised. It must be a valid RFC 5322 address without a display name, or
// Zitadel's own validation rejects it.
func TestNewClaimsSynthesisesAValidEmailAddress(t *testing.T) {
	t.Parallel()

	claims, err := app.NewClaims(identity(t, details()), emailDomain)
	if err != nil {
		t.Fatalf("NewClaims returned error: %v", err)
	}

	if !strings.HasSuffix(claims.Email, "@"+emailDomain) {
		t.Errorf("Email = %q, want it under %q", claims.Email, emailDomain)
	}

	address, err := mail.ParseAddress(claims.Email)
	if err != nil {
		t.Fatalf("mail.ParseAddress(%q) returned error: %v", claims.Email, err)
	}

	if address.Name != "" {
		t.Errorf("the address carries display name %q; Zitadel rejects those", address.Name)
	}

	// The verified flag stops Zitadel from sending a confirmation code to
	// an address that can never receive mail.
	if !claims.EmailVerified {
		t.Error("EmailVerified = false; Zitadel would then mail a code to an undeliverable address")
	}
}

// If the certificate does carry a real address, against expectation, it must be
// used instead.
func TestNewClaimsPrefersTheCertificatesOwnEmail(t *testing.T) {
	t.Parallel()

	d := details()
	d.Email = "anna.andersson@agency.example.se"

	claims, err := app.NewClaims(identity(t, d), emailDomain)
	if err != nil {
		t.Fatalf("NewClaims returned error: %v", err)
	}

	if claims.Email != "anna.andersson@agency.example.se" {
		t.Errorf("Email = %q, want the certificate's own address", claims.Email)
	}

	if claims.EmailVerified {
		t.Error("EmailVerified = true for an address we have not confirmed")
	}
}

func TestNewClaimsRequiresAnEmailDomain(t *testing.T) {
	t.Parallel()

	for _, domainName := range []string{"", "   ", "not a domain", "@example.se"} {
		_, err := app.NewClaims(identity(t, details()), domainName)
		if !errors.Is(err, app.ErrInvalidEmailDomain) {
			t.Errorf("NewClaims with domain %q: error = %v, want ErrInvalidEmailDomain",
				domainName, err)
		}
	}
}
