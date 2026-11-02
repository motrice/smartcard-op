// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package audit writes the authentication audit trail.
//
// The package owns its own record type rather than the use case's. That is
// deliberate: the wire format is what gets retained for years and read by
// auditors, so it should be able to change independently of the use case's
// internal struct — and it is here that retention, redaction and access are
// reasoned about.
//
// Records are hash-chained. That makes the log tamper-evident without a
// write-once store, and it detects deletion as well as modification: removing a
// record breaks the links of every record after it.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	// ErrUnusableConfig wraps a configuration the log refuses to start with.
	ErrUnusableConfig = errors.New("unusable audit configuration")
	// ErrChainBroken wraps every way a log can fail verification. An
	// auditor cares which record broke, which the message carries, but
	// programmatically there is one question: can this log be trusted.
	ErrChainBroken = errors.New("the audit chain is broken")
)

// minimumHMACKeyLength is the floor for the redaction key. A twelve-digit
// identity number has only a few billion possible values, so an unkeyed digest
// would be reversible by brute force in seconds; the key is what makes the
// hashed form meaningful, and a short key is barely better than none.
const minimumHMACKeyLength = 16

// Redaction is how the personal identity number is written to the log.
type Redaction string

const (
	// RedactionHashed writes a keyed HMAC. It is the default: stable enough
	// for an investigator to correlate two logins by the same person,
	// without putting a personal identity number in a log retained for
	// years. GDPR Article 5(1)(c), and the Swedish rule that processing an
	// identity number needs clear justification.
	RedactionHashed Redaction = "hashed"
	// RedactionMasked keeps the birth date and masks the last four digits.
	RedactionMasked Redaction = "masked"
	// RedactionFull writes the number as it is. Choose it only where the
	// log platform's retention and access controls justify it.
	RedactionFull Redaction = "full"
)

// Config configures the log.
type Config struct {
	// Redaction defaults to RedactionHashed.
	Redaction Redaction
	// HMACKey keys the hashed redaction. Required for RedactionHashed.
	HMACKey []byte
	// Identifier names this instance in the genesis record, so that two
	// instances' chains can be told apart.
	Identifier string
	// Now is overridable for tests.
	Now func() time.Time
}

// Record is one authentication attempt, in the shape it is retained in.
type Record struct {
	Granted                bool
	Reason                 string
	Fingerprint            string
	CertificateSerial      string
	Issuer                 string
	CertificateNotAfter    time.Time
	PersonalIdentityNumber string
	AssuranceLevel         uint8
	Organization           string
	RevocationMethod       string
	RevocationStatus       string
	RevocationFromCache    bool
	RevokedAt              time.Time
	Duration               time.Duration
}

// entry is the serialised form. The field names are the log's contract with
// whoever queries it, so they are spelled out rather than derived.
type entry struct {
	Timestamp           string `json:"ts"`
	Event               string `json:"event"`
	Outcome             string `json:"outcome"`
	Reason              string `json:"reason"`
	CertSHA256          string `json:"cert_sha256"`
	CertSerial          string `json:"cert_serial,omitempty"`
	CertIssuer          string `json:"cert_issuer,omitempty"`
	CertNotAfter        string `json:"cert_not_after,omitempty"`
	SubjectID           string `json:"subject_id,omitempty"`
	SubjectIDForm       string `json:"subject_id_form"`
	AssuranceLevel      uint8  `json:"assurance_level,omitempty"`
	Organization        string `json:"organization,omitempty"`
	RevocationMethod    string `json:"revocation_method,omitempty"`
	RevocationStatus    string `json:"revocation_status,omitempty"`
	RevocationFromCache bool   `json:"revocation_cached,omitempty"`
	RevokedAt           string `json:"revoked_at,omitempty"`
	DurationMS          int64  `json:"duration_ms"`
	Sequence            uint64 `json:"seq"`
	Previous            string `json:"prev"`
	Chain               string `json:"chain"`
}

// Log writes audit records to a stream, one JSON object per line.
type Log struct {
	config Config
	writer io.Writer

	mutex    sync.Mutex
	sequence uint64
	previous string
}

// New builds the log.
//
// It validates up front rather than on the first record: a log that cannot
// redact as configured must stop the service from starting, not discover the
// problem once it already holds personal data.
func New(writer io.Writer, config Config) (*Log, error) {
	if config.Redaction == "" {
		config.Redaction = RedactionHashed
	}

	switch config.Redaction {
	case RedactionHashed:
		if len(config.HMACKey) < minimumHMACKeyLength {
			return nil, fmt.Errorf(
				"%w: hashed redaction needs a key of at least %d bytes; "+
					"an unkeyed digest of a twelve-digit number is reversible by brute force",
				ErrUnusableConfig, minimumHMACKeyLength)
		}
	case RedactionMasked, RedactionFull:
	default:
		return nil, fmt.Errorf("%w: unknown redaction %q", ErrUnusableConfig, config.Redaction)
	}

	if config.Now == nil {
		config.Now = time.Now
	}

	log := &Log{config: config, writer: writer}

	// The genesis value anchors the chain to this instance, so that two
	// instances' logs cannot be spliced together unnoticed.
	genesis := sha256.Sum256([]byte("smartcard-op/audit/v1/" + config.Identifier))
	log.previous = base64.RawURLEncoding.EncodeToString(genesis[:])

	return log, nil
}

// Genesis returns the chain's anchor, which should be recorded at startup so
// that the first record can be verified later.
func (l *Log) Genesis() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.previous
}

// Write appends a record.
//
// Writing never fails the caller: an authentication must not be denied because
// the log platform is unreachable, and a lost record is a lesser harm than a
// user locked out by an unrelated outage. The write error is surfaced on the
// stream itself, which is where an operator is watching.
func (l *Log) Write(record Record) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.sequence++

	written := entry{
		Timestamp:           l.config.Now().UTC().Format(time.RFC3339Nano),
		Event:               "efos.auth.attempt",
		Outcome:             outcome(record.Granted),
		Reason:              record.Reason,
		CertSHA256:          record.Fingerprint,
		CertSerial:          record.CertificateSerial,
		CertIssuer:          record.Issuer,
		SubjectID:           l.redact(record.PersonalIdentityNumber),
		SubjectIDForm:       string(l.config.Redaction),
		AssuranceLevel:      record.AssuranceLevel,
		Organization:        record.Organization,
		RevocationMethod:    record.RevocationMethod,
		RevocationStatus:    record.RevocationStatus,
		RevocationFromCache: record.RevocationFromCache,
		DurationMS:          record.Duration.Milliseconds(),
		Sequence:            l.sequence,
		Previous:            l.previous,
	}

	if !record.CertificateNotAfter.IsZero() {
		written.CertNotAfter = record.CertificateNotAfter.UTC().Format(time.RFC3339)
	}

	if !record.RevokedAt.IsZero() {
		written.RevokedAt = record.RevokedAt.UTC().Format(time.RFC3339)
	}

	chain, err := chainHash(written)
	if err != nil {
		_, _ = fmt.Fprintf(
			l.writer, "{\"event\":\"efos.audit.error\",\"error\":%q}\n", err.Error())

		return
	}

	written.Chain = chain
	l.previous = chain

	encoded, err := json.Marshal(written)
	if err != nil {
		_, _ = fmt.Fprintf(
			l.writer, "{\"event\":\"efos.audit.error\",\"error\":%q}\n", err.Error())

		return
	}

	if _, err := fmt.Fprintf(l.writer, "%s\n", encoded); err != nil {
		// Nothing useful remains to be done: the stream we would report
		// the failure on is the one that failed.
		_ = err
	}
}

// redact renders the identity number as configured.
func (l *Log) redact(number string) string {
	if number == "" {
		return ""
	}

	switch l.config.Redaction {
	case RedactionFull:
		return number
	case RedactionMasked:
		if len(number) <= 4 {
			return "****"
		}

		return number[:len(number)-4] + "****"
	default:
		mac := hmac.New(sha256.New, l.config.HMACKey)
		_, _ = mac.Write([]byte(number))

		return "hmac:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
}

func outcome(granted bool) string {
	if granted {
		return "granted"
	}

	return "denied"
}

// chainHash hashes the record's canonical form together with the previous
// chain value. The chain field itself is empty at this point, so the hash
// covers exactly what is written apart from the hash.
func chainHash(written entry) (string, error) {
	canonical, err := json.Marshal(written)
	if err != nil {
		return "", fmt.Errorf("could not canonicalise the record: %w", err)
	}

	sum := sha256.Sum256(canonical)

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Verify walks a log stream and checks that the chain holds.
//
// It reports the first record whose links do not match, which is what an
// auditor needs: the point at which the log stopped being trustworthy.
func Verify(stream io.Reader) error {
	decoder := json.NewDecoder(stream)

	var (
		previous string
		sequence uint64
	)

	for {
		var written entry

		if err := decoder.Decode(&written); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("could not read the log: %w", err)
		}

		if sequence != 0 && written.Sequence != sequence+1 {
			return fmt.Errorf(
				"%w: a record is missing, sequence jumped from %d to %d",
				ErrChainBroken, sequence, written.Sequence)
		}

		if previous != "" && written.Previous != previous {
			return fmt.Errorf("%w: record %d does not link to its predecessor",
				ErrChainBroken, written.Sequence)
		}

		claimed := written.Chain
		written.Chain = ""

		recomputed, err := chainHash(written)
		if err != nil {
			return err
		}

		if recomputed != claimed {
			return fmt.Errorf("%w: record %d has been altered", ErrChainBroken, written.Sequence)
		}

		previous = claimed
		sequence = written.Sequence
	}
}
