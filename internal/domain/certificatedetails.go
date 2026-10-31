// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package domain

import (
	"slices"
	"time"
)

// Object identifiers for the extended key usage the EFOS profile prescribes
// for the authentication certificate.
const (
	// OIDClientAuth is id-kp-clientAuth, RFC 5280.
	OIDClientAuth = "1.3.6.1.5.5.7.3.2"
	// OIDSmartcardLogon is Microsoft's szOID_KP_SMARTCARD_LOGON, which the
	// EFOS profile requires alongside clientAuth.
	OIDSmartcardLogon = "1.3.6.1.4.1.311.20.2.2"
)

// CertificateDetails is what has been read out of a client certificate,
// expressed as plain values. The domain never touches crypto/x509 itself:
// translating a certificate into this struct belongs to an adapter, which makes
// every domain rule testable without building a certificate first.
//
// The fields follow EFOS End Entity Person Certificates rev 1.6.
type CertificateDetails struct {
	// SubjectSerialNumber is the subject:serialNumber attribute
	// (OID 2.5.4.5), which the profile says carries the personal identity
	// number. It is not the certificate's own serial number.
	SubjectSerialNumber string
	// EfosID is subject:title (OID 2.5.4.12).
	EfosID string
	// GivenName is subject:givenName (OID 2.5.4.42). May be empty.
	GivenName string
	// FamilyName is subject:surname (OID 2.5.4.4).
	FamilyName string
	// CommonName is subject:commonName (OID 2.5.4.3).
	CommonName string
	// Organization is subject:organizationName (OID 2.5.4.10).
	Organization string
	// OrganizationNumberRaw is subject:organizationalUnitName
	// (OID 2.5.4.11), which the profile says carries the organization
	// number.
	OrganizationNumberRaw string
	// Email is the rfc822Name from subjectAltName. The EFOS profile
	// dropped the email field in rev 1.5, so it is normally empty — but a
	// certificate that does carry an address is preferable to a synthetic
	// one.
	Email string
	// PolicyOIDs holds the certificate's policy identifiers.
	PolicyOIDs []string
	// ExtendedKeyUsage holds the certificate's extended key usage as OID
	// strings.
	ExtendedKeyUsage []string
	// HasDigitalSignature reports whether keyUsage includes
	// digitalSignature.
	HasDigitalSignature bool
	// NotBefore and NotAfter bound the certificate's validity.
	NotBefore time.Time
	NotAfter  time.Time
}

// hasExtendedKeyUsage reports whether the certificate carries a given extended
// key usage.
func (c CertificateDetails) hasExtendedKeyUsage(oid string) bool {
	return slices.Contains(c.ExtendedKeyUsage, oid)
}
