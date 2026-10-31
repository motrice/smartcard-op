// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import "time"

// RevocationStatus is the outcome of a revocation check against EFOS.
//
// The zero value is RevocationStatusUnknown, and that is deliberate: a status
// that was never filled in must never be able to let anyone through.
type RevocationStatus uint8

const (
	// RevocationStatusUnknown means no binding answer was obtained — either
	// the responder said "unknown" or it could not be reached.
	RevocationStatusUnknown RevocationStatus = iota
	// RevocationStatusValid means EFOS expressly attested that the
	// certificate is not revoked.
	RevocationStatusValid
	// RevocationStatusRevoked means the certificate has been revoked.
	RevocationStatusRevoked
)

// PermitsLogin reports whether the status suffices to authenticate someone.
//
// Only an express "valid" does. EFOS CP section 4.9.6 obliges relying parties
// to check revocation status, and a check that lets a request through when the
// answer is missing would be decorative: whoever stole a card would only have
// to make the responder unreachable to defeat it. The cost of denying is a
// visible, actionable outage; the cost of permitting is an undetectable login
// with a known-compromised credential.
func (r RevocationStatus) PermitsLogin() bool {
	return r == RevocationStatusValid
}

// String describes the status in logs and error messages.
func (r RevocationStatus) String() string {
	switch r {
	case RevocationStatusValid:
		return "valid"
	case RevocationStatusRevoked:
		return "revoked"
	default:
		return "unknown revocation status"
	}
}

// RevocationMethod is how a revocation verdict was obtained. EFOS CP section
// 4.9.6 accepts either, but which one was used is evidence an investigator
// needs afterwards.
type RevocationMethod string

const (
	// RevocationMethodOCSP is a direct answer from the EFOS responder.
	RevocationMethodOCSP RevocationMethod = "ocsp"
	// RevocationMethodCRL is a certificate revocation list.
	RevocationMethodCRL RevocationMethod = "crl"
)

// RevocationVerdict is the outcome of a revocation check together with the
// evidence for it.
//
// The evidence belongs to the domain rather than to the adapter that fetched
// it: the decision to deny or permit is made on its basis, and the audit log
// must be able to show exactly what the decision rested on.
type RevocationVerdict struct {
	Status RevocationStatus
	Method RevocationMethod
	// IssuedAt is when EFOS issued the verdict, not when we read it.
	IssuedAt time.Time
	// ValidUntil is the verdict's own validity: nextUpdate in an OCSP
	// response or in a revocation list.
	ValidUntil time.Time
	// RevokedAt is the revocation time, when the status is revoked.
	RevokedAt time.Time
	// Reason is the CRLReason code, when the status is revoked.
	Reason int
	// FromCache reports whether the verdict came from our own cache rather
	// than over the network.
	FromCache bool
}

// PermitsLogin reports whether the verdict suffices to authenticate someone.
func (r RevocationVerdict) PermitsLogin() bool {
	return r.Status.PermitsLogin()
}
