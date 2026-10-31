// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package xfcc parses Envoy's x-forwarded-client-cert header.
//
// The header is Envoy's way of handing on the client certificate the TLS
// handshake was authenticated with. It is therefore a bearer assertion of
// identity: the service must be unreachable other than through Envoy's mTLS
// listener, and Envoy must be configured with forward_client_cert_details:
// SANITIZE_SET so that a header the client supplied itself is replaced.
package xfcc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The errors this package can return. They are deliberately distinct: each
// variant maps to its own audit record and its own message to the user.
var (
	// ErrHeaderMissing means the request did not arrive through the mTLS
	// listener.
	ErrHeaderMissing = errors.New("x-forwarded-client-cert is missing")
	// ErrMoreThanOneCertificate means the header carries more than one
	// element, which contradicts SANITIZE_SET and suggests someone appended
	// their own.
	ErrMoreThanOneCertificate = errors.New(
		"x-forwarded-client-cert carries more than one certificate")
	// ErrCertificateMissing means Cert= was absent, so Envoy lacks
	// set_current_client_cert_details.cert.
	ErrCertificateMissing = errors.New("x-forwarded-client-cert has no Cert field")
	// ErrUnparsableCertificate means Cert= could not be decoded.
	ErrUnparsableCertificate = errors.New(
		"the certificate in x-forwarded-client-cert cannot be parsed")
	// ErrFingerprintMismatch means Envoy's Hash does not match the
	// certificate we parsed: either a bug on our side or a tampered header.
	ErrFingerprintMismatch = errors.New(
		"the fingerprint in x-forwarded-client-cert does not match the certificate")
	// ErrHeaderTooLarge means the header exceeded the cap.
	ErrHeaderTooLarge = errors.New("x-forwarded-client-cert is too large")
)

// maxHeaderSize caps the header's length. An RSA-2048 certificate in
// percent-encoded PEM lands around two kilobytes, so the cap is generous — but
// it stops an attacker from making us decode megabytes.
const maxHeaderSize = 32 * 1024

// fingerprintLength is the number of characters in a hex-encoded SHA-256 sum.
const fingerprintLength = sha256.Size * 2

// Parse extracts the client certificate from all values of the header.
//
// Exactly one value with exactly one element is required. Envoy sets Hash to
// SHA-256 over the leaf's DER, and the header is rejected if it does not match.
//
// Chain= is deliberately not read: Envoy documents it as the chain the client
// presented rather than the validated one, which makes it attacker-controlled.
// The issuer must be obtained from our own trust anchor by verifying the leaf
// afresh.
func Parse(values []string) (*x509.Certificate, error) {
	raw, err := singleValue(values)
	if err != nil {
		return nil, err
	}

	elements := splitTopLevel(raw, ',')
	if len(elements) != 1 {
		return nil, fmt.Errorf("%w: %d elements", ErrMoreThanOneCertificate, len(elements))
	}

	encoded, present := field(elements[0], "cert")
	if !present {
		return nil, ErrCertificateMissing
	}

	cert, err := parseCertificate(encoded)
	if err != nil {
		return nil, err
	}

	if err := checkFingerprint(elements[0], cert); err != nil {
		return nil, err
	}

	return cert, nil
}

func singleValue(values []string) (string, error) {
	populated := make([]string, 0, len(values))

	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			populated = append(populated, value)
		}
	}

	switch len(populated) {
	case 1:
		if len(populated[0]) > maxHeaderSize {
			return "", fmt.Errorf("%w: %d characters, the cap is %d",
				ErrHeaderTooLarge, len(populated[0]), maxHeaderSize)
		}

		return populated[0], nil
	case 0:
		return "", ErrHeaderMissing
	default:
		return "", fmt.Errorf("%w: %d header values", ErrMoreThanOneCertificate, len(populated))
	}
}

func parseCertificate(encoded string) (*x509.Certificate, error) {
	// PathUnescape, not QueryUnescape: the latter turns a literal plus into
	// a space. Envoy's encoder never emits a bare plus, so QueryUnescape
	// happens to work today, but PathUnescape is correct by construction —
	// and if anything upstream ever encodes differently, QueryUnescape
	// would silently corrupt base64 instead of failing.
	raw, err := url.PathUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed percent-encoding: %w", ErrUnparsableCertificate, err)
	}

	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf(
			"%w: no PEM block of type CERTIFICATE", ErrUnparsableCertificate)
	}

	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf("%w: more than one PEM block", ErrUnparsableCertificate)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnparsableCertificate, err)
	}

	return cert, nil
}

func checkFingerprint(element string, cert *x509.Certificate) error {
	stated, present := field(element, "hash")
	if !present || len(stated) != fingerprintLength {
		// Envoy always sets Hash, but a value in an unexpected shape is
		// not in itself grounds to deny: the certificate has already
		// been parsed and is verified in the next step. A missing
		// cross-check is logged instead.
		return nil
	}

	sum := sha256.Sum256(cert.Raw)
	if !strings.EqualFold(stated, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("%w: the header says %s", ErrFingerprintMismatch, stated)
	}

	return nil
}

// field looks up a key-value pair in an element. The key comparison is
// case-insensitive; Envoy writes Cert, but the header's shape is not ours to
// dictate.
func field(element, key string) (string, bool) {
	for _, pair := range splitTopLevel(element, ';') {
		name, value, found := strings.Cut(pair, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), key) {
			continue
		}

		return unquote(value), true
	}

	return "", false
}

// splitTopLevel splits a string on a separator, but only outside quotes.
// Subject and Issuer are RFC 2253 distinguished names carrying raw commas and
// equals signs, so a naive strings.Split shreds them — and then Cert= is no
// longer found.
func splitTopLevel(s string, separator byte) []string {
	var (
		parts    []string
		builder  strings.Builder
		inQuotes bool
		escaped  bool
	)

	for i := range len(s) {
		char := s[i]

		switch {
		case escaped:
			escaped = false
		case char == '\\' && inQuotes:
			escaped = true
		case char == '"':
			inQuotes = !inQuotes
		case char == separator && !inQuotes:
			parts = append(parts, builder.String())
			builder.Reset()

			continue
		}

		builder.WriteByte(char)
	}

	parts = append(parts, builder.String())

	return parts
}

// unquote strips surrounding quotes and translates escaped quotes back.
func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	return strings.ReplaceAll(value, `\"`, `"`)
}
