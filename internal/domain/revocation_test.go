// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain_test

import (
	"testing"

	"github.com/motrice/smartcard-op/internal/domain"
)

// EFOS CP section 4.9.6 obliges relying parties to check revocation status. A
// check that lets a request through when the answer is missing is decorative:
// whoever stole a card would only need to make the responder unreachable to
// defeat it. Only an express "valid" may therefore permit a login.
func TestRevocationStatusPermitsOnlyExpressValid(t *testing.T) {
	t.Parallel()

	cases := map[domain.RevocationStatus]bool{
		domain.RevocationStatusValid:   true,
		domain.RevocationStatusRevoked: false,
		domain.RevocationStatusUnknown: false,
	}

	for status, want := range cases {
		if got := status.PermitsLogin(); got != want {
			t.Errorf("%v.PermitsLogin() = %t, want %t", status, got, want)
		}
	}
}

// The zero value must be the denying one. A fresh RevocationStatus{} that
// happened to mean "valid" would silently bypass the entire check.
func TestRevocationStatusZeroValueDenies(t *testing.T) {
	t.Parallel()

	var untouched domain.RevocationStatus

	if untouched.PermitsLogin() {
		t.Error("the zero value permits login")
	}

	if untouched != domain.RevocationStatusUnknown {
		t.Errorf("zero value = %v, want RevocationStatusUnknown", untouched)
	}
}

func TestRevocationStatusIsDescribedInLogs(t *testing.T) {
	t.Parallel()

	want := map[domain.RevocationStatus]string{
		domain.RevocationStatusValid:   "valid",
		domain.RevocationStatusRevoked: "revoked",
		domain.RevocationStatusUnknown: "unknown revocation status",
	}

	for status, text := range want {
		if got := status.String(); got != text {
			t.Errorf("String() = %q, want %q", got, text)
		}
	}
}

// The verdict must inherit the status's denial, so that a caller holding only
// the verdict cannot accidentally be more permissive.
func TestRevocationVerdictInheritsTheStatusDecision(t *testing.T) {
	t.Parallel()

	var empty domain.RevocationVerdict

	if empty.PermitsLogin() {
		t.Error("an empty verdict permits login")
	}

	valid := domain.RevocationVerdict{Status: domain.RevocationStatusValid}
	if !valid.PermitsLogin() {
		t.Error("a valid verdict does not permit login")
	}
}
