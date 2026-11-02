// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"

	"github.com/motrice/smartcard-op/internal/adapters/audit"
	"github.com/motrice/smartcard-op/internal/app"
)

// auditWriter adapts the use case's audit port to the audit log's own record.
//
// The translation lives here, in the composition root, for a reason worth
// stating: the audit log's record is the shape retained for years and read by
// auditors, and the use case's event is its own internal structure. Letting the
// adapter take the use case's type would have made the wire format hostage to a
// refactor of the use case, and would have inverted the dependency arrow — the
// layer rules would have caught the second part, but not the first.
type auditWriter struct {
	log *audit.Log
}

// Write satisfies app.AuditLog.
func (a auditWriter) Write(event app.AuditEvent) {
	record := audit.Record{
		Granted:                event.Granted,
		Reason:                 event.Reason,
		Fingerprint:            event.Fingerprint,
		CertificateSerial:      event.CertificateSerialNumber,
		Issuer:                 event.Issuer,
		PersonalIdentityNumber: event.PersonalIdentityNumber,
		AssuranceLevel:         uint8(event.AssuranceLevel),
		RevocationMethod:       string(event.RevocationVerdict.Method),
		RevocationStatus:       event.RevocationVerdict.Status.String(),
		RevocationFromCache:    event.RevocationVerdict.FromCache,
		RevokedAt:              event.RevocationVerdict.RevokedAt,
		Duration:               event.Duration,
	}

	a.log.Write(record)
}

// fingerprintOf is the same correlation key the use case records, computed here
// so that a page can show its prefix before the use case has run.
func fingerprintOf(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}

	sum := sha256.Sum256(certificate.Raw)

	return hex.EncodeToString(sum[:])
}
