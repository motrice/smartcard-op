// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package efospki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"

	"github.com/motrice/smartcard-op/internal/domain"
)

var (
	// ErrUnreadableDN wraps DN attributes whose ASN.1 value is not a
	// string. Go skips those silently, which would surface as an
	// incomprehensible "invalid personal identity number" rather than the
	// truth.
	ErrUnreadableDN = errors.New("the certificate's dn cannot be read")
	// ErrAmbiguousDN wraps distinguished names that carry the same
	// attribute more than once. Go then silently keeps the last one, so the
	// outcome would depend on the order within the certificate.
	ErrAmbiguousDN = errors.New("the certificate's dn is ambiguous")
)

// Object identifiers in the EFOS subject DN.
//
// Go's pkix.FillFromRDNSequence only maps OID 2.5.4.{3,5,6,7,8,9,10,11,17} to
// named fields. serialNumber (2.5.4.5) is therefore available as
// Subject.SerialNumber, but title, givenName and surname must be read from
// Subject.Names by OID.
var (
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSurname            = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidTitle              = asn1.ObjectIdentifier{2, 5, 4, 12}
	oidGivenName          = asn1.ObjectIdentifier{2, 5, 4, 42}
)

// extKeyUsageToOID translates Go's named extended key usages back into OID
// strings, because the domain expresses its rules in OIDs and never touches
// crypto/x509.
var extKeyUsageToOID = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "2.5.29.37.0",
	x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth:                     "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
	x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
	x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

// Reader translates an EFOS certificate into the plain values the domain tests
// its rules against.
type Reader struct{}

// NewReader creates the reader. It is stateless.
func NewReader() *Reader { return &Reader{} }

// Read extracts the certificate's details.
//
// The reader rejects only what is unreadable or ambiguous. Missing fields are
// left empty and are the domain's business to judge — it owns the rules and
// should get to say so with its own errors, so that the user is met by "the
// card lacks required information" rather than by a reader fault.
func (Reader) Read(card *x509.Certificate) (domain.CertificateDetails, error) {
	if card == nil {
		return domain.CertificateDetails{}, fmt.Errorf("%w: no certificate", ErrUnreadableDN)
	}

	attributes, err := attributesByOID(card.Subject)
	if err != nil {
		return domain.CertificateDetails{}, err
	}

	fields := make(map[string]string, 7)

	for name, oid := range map[string]asn1.ObjectIdentifier{
		"subjectSerialNumber": oidSerialNumber,
		"efosID":              oidTitle,
		"givenName":           oidGivenName,
		"familyName":          oidSurname,
		"commonName":          oidCommonName,
		"organization":        oidOrganization,
		"organizationNumber":  oidOrganizationalUnit,
	} {
		value, err := atMostOne(attributes, oid)
		if err != nil {
			return domain.CertificateDetails{}, err
		}

		fields[name] = value
	}

	return domain.CertificateDetails{
		SubjectSerialNumber:   fields["subjectSerialNumber"],
		EfosID:                fields["efosID"],
		GivenName:             fields["givenName"],
		FamilyName:            fields["familyName"],
		CommonName:            fields["commonName"],
		Organization:          fields["organization"],
		OrganizationNumberRaw: fields["organizationNumber"],
		Email:                 firstEmail(card),
		PolicyOIDs:            policyOIDs(card),
		ExtendedKeyUsage:      extendedKeyUsage(card),
		HasDigitalSignature:   card.KeyUsage&x509.KeyUsageDigitalSignature != 0,
		NotBefore:             card.NotBefore,
		NotAfter:              card.NotAfter,
	}, nil
}

// attributesByOID collects every DN attribute per OID, in the order they
// appeared.
//
// Subject.Names is used, not ExtraNames: ExtraNames is an outbound field that
// is only populated when Go builds a DN itself, and is empty on a parsed
// certificate. Names carries every attribute encountered — including those Go
// does not map to a named field.
func attributesByOID(name pkix.Name) (map[string][]string, error) {
	attributes := make(map[string][]string, len(name.Names))

	for _, pair := range name.Names {
		value, isString := pair.Value.(string)
		if !isString {
			return nil, fmt.Errorf(
				"%w: the attribute %s carries an asn.1 value of type %T rather than a string",
				ErrUnreadableDN, pair.Type, pair.Value)
		}

		key := pair.Type.String()
		attributes[key] = append(attributes[key], strings.TrimSpace(value))
	}

	return attributes, nil
}

// atMostOne returns the attribute's value, the empty string if it is absent,
// and an error if it occurs more than once.
func atMostOne(attributes map[string][]string, oid asn1.ObjectIdentifier) (string, error) {
	values := attributes[oid.String()]

	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("%w: the attribute %s occurs %d times",
			ErrAmbiguousDN, oid, len(values))
	}
}

// extendedKeyUsage merges both extended key usage fields into OID strings.
//
// Go moves known identifiers into ExtKeyUsage and leaves the rest in
// UnknownExtKeyUsage. EFOS requires both clientAuth, which Go knows, and
// smartcardLogon, for which it has no constant — read only one field and the
// domain never sees both, and rejects every card.
func extendedKeyUsage(card *x509.Certificate) []string {
	usages := make([]string, 0, len(card.ExtKeyUsage)+len(card.UnknownExtKeyUsage))

	for _, usage := range card.ExtKeyUsage {
		if oid, known := extKeyUsageToOID[usage]; known {
			usages = append(usages, oid)
		}
	}

	for _, oid := range card.UnknownExtKeyUsage {
		usages = append(usages, oid.String())
	}

	return usages
}

// policyOIDs reads the certificate's policy identifiers.
//
// Policies is the field added in Go 1.22; PolicyIdentifiers is deprecated and
// silently drops identifiers whose arcs exceed int32. The deprecated field is
// read only as a fallback, for certificates where the new one is empty for some
// reason.
func policyOIDs(card *x509.Certificate) []string {
	if len(card.Policies) > 0 {
		oids := make([]string, 0, len(card.Policies))
		for _, policy := range card.Policies {
			oids = append(oids, policy.String())
		}

		return oids
	}

	oids := make([]string, 0, len(card.PolicyIdentifiers))
	for _, policy := range card.PolicyIdentifiers {
		oids = append(oids, policy.String())
	}

	return oids
}

// firstEmail returns the certificate's rfc822Name if it carries one. The EFOS
// profile dropped the email field in rev 1.5, so it is normally empty.
func firstEmail(card *x509.Certificate) string {
	for _, address := range card.EmailAddresses {
		if trimmed := strings.TrimSpace(address); trimmed != "" {
			return trimmed
		}
	}

	return ""
}
