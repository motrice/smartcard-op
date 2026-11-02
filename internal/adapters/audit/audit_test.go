// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/motrice/smartcard-op/internal/adapters/audit"
)

func record() audit.Record {
	return audit.Record{
		Granted:                true,
		Reason:                 "granted",
		Fingerprint:            strings.Repeat("a3f1", 16),
		CertificateSerial:      "4711",
		Issuer:                 "CN=Swedish Public Sector Person 3 CA v1,C=SE",
		PersonalIdentityNumber: "195606019577",
		AssuranceLevel:         3,
		RevocationMethod:       "ocsp",
		RevocationStatus:       "valid",
		Duration:               214 * time.Millisecond,
	}
}

// decode reads the newline-delimited JSON the log writes.
func decode(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()

	var entries []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(buffer.String()), "\n") {
		if line == "" {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("could not decode %q: %v", line, err)
		}

		entries = append(entries, entry)
	}

	return entries
}

func TestWriteEmitsTheRecordAsJSON(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	log, err := audit.New(&buffer, audit.Config{
		Redaction:  audit.RedactionFull,
		Identifier: "test",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	log.Write(record())

	entries := decode(t, &buffer)
	if len(entries) != 1 {
		t.Fatalf("%d entries, want 1", len(entries))
	}

	entry := entries[0]
	for field, want := range map[string]any{
		"outcome":           "granted",
		"reason":            "granted",
		"cert_serial":       "4711",
		"revocation_method": "ocsp",
		"revocation_status": "valid",
	} {
		if entry[field] != want {
			t.Errorf("%s = %v, want %v", field, entry[field], want)
		}
	}

	if entry["cert_sha256"] == "" || entry["cert_sha256"] == nil {
		t.Error("cert_sha256 is absent; it is the correlation key")
	}

	if entry["ts"] == nil {
		t.Error("ts is absent")
	}
}

// A denial must be as legible as a success. An operator counting denials by
// reason is the first signal that something is wrong with a card population.
func TestWriteRecordsDenials(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	log, err := audit.New(&buffer, audit.Config{Redaction: audit.RedactionFull})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	denied := record()
	denied.Granted = false
	denied.Reason = "revoked"
	denied.RevocationStatus = "revoked"
	denied.RevokedAt = time.Date(2026, time.October, 28, 13, 16, 45, 0, time.UTC)

	log.Write(denied)

	entry := decode(t, &buffer)[0]
	if entry["outcome"] != "denied" {
		t.Errorf("outcome = %v, want denied", entry["outcome"])
	}

	if entry["reason"] != "revoked" {
		t.Errorf("reason = %v, want revoked", entry["reason"])
	}

	if entry["revoked_at"] == nil {
		t.Error("revoked_at is absent for a revoked card")
	}
}

// The identity number is personal data in a log retained for years. The
// default must therefore be the protective one, so that an operator who never
// thinks about it still gets the safe behaviour.
func TestRedactionDefaultsToHashed(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	log, err := audit.New(&buffer, audit.Config{HMACKey: []byte("a-key-of-sufficient-length-here")})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	log.Write(record())

	entry := decode(t, &buffer)[0]

	number, _ := entry["subject_id"].(string)
	if strings.Contains(number, "195606019577") {
		t.Errorf("subject_id = %q; the identity number is in the clear by default", number)
	}

	if number == "" {
		t.Error("subject_id is absent; an investigator needs something to pivot on")
	}
}

func TestRedactionModes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mode  audit.Redaction
		check func(*testing.T, string)
	}{
		"full keeps the number": {
			mode: audit.RedactionFull,
			check: func(t *testing.T, got string) {
				t.Helper()

				if got != "195606019577" {
					t.Errorf("subject_id = %q, want the number", got)
				}
			},
		},
		"masked keeps the birth date only": {
			mode: audit.RedactionMasked,
			check: func(t *testing.T, got string) {
				t.Helper()

				if got != "19560601****" {
					t.Errorf("subject_id = %q, want 19560601****", got)
				}
			},
		},
		"hashed reveals nothing": {
			mode: audit.RedactionHashed,
			check: func(t *testing.T, got string) {
				t.Helper()

				if strings.Contains(got, "195606019577") || got == "" {
					t.Errorf("subject_id = %q", got)
				}
			},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			log, err := audit.New(&buffer, audit.Config{
				Redaction: testCase.mode,
				HMACKey:   []byte("a-key-of-sufficient-length-here"),
			})
			if err != nil {
				t.Fatalf("New returned error: %v", err)
			}

			log.Write(record())

			number, _ := decode(t, &buffer)[0]["subject_id"].(string)
			testCase.check(t, number)
		})
	}
}

// The hashed form has to be stable, or an investigator could not correlate two
// logins by the same person — which is most of what the field is for.
func TestHashedRedactionIsStableAndKeyed(t *testing.T) {
	t.Parallel()

	hash := func(t *testing.T, key string) string {
		t.Helper()

		var buffer bytes.Buffer

		log, err := audit.New(&buffer, audit.Config{
			Redaction: audit.RedactionHashed,
			HMACKey:   []byte(key),
		})
		if err != nil {
			t.Fatalf("New returned error: %v", err)
		}

		log.Write(record())

		number, _ := decode(t, &buffer)[0]["subject_id"].(string)

		return number
	}

	const key = "a-key-of-sufficient-length-here"

	first := hash(t, key)
	if first != hash(t, key) {
		t.Error("the same key gave two different hashes")
	}

	if first == hash(t, "a-different-key-of-sufficient-len") {
		t.Error("two different keys gave the same hash; the hash is not keyed")
	}
}

// Hashing without a key would be a plain digest of a twelve-digit number,
// which is trivially reversible by brute force. Refusing to start is the only
// honest behaviour.
func TestNewRefusesHashedRedactionWithoutAKey(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	_, err := audit.New(&buffer, audit.Config{Redaction: audit.RedactionHashed})
	if !errors.Is(err, audit.ErrUnusableConfig) {
		t.Fatalf("error = %v, want ErrUnusableConfig", err)
	}

	_, err = audit.New(&buffer, audit.Config{
		Redaction: audit.RedactionHashed,
		HMACKey:   []byte("short"),
	})
	if !errors.Is(err, audit.ErrUnusableConfig) {
		t.Fatalf("a short key was accepted: %v", err)
	}
}

// The chain makes the log tamper-evident without a write-once store, and it
// detects deletion as well as modification: a missing record breaks the links
// of everything after it.
func TestRecordsAreHashChained(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	log, err := audit.New(&buffer, audit.Config{
		Redaction:  audit.RedactionFull,
		Identifier: "instance-1",
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	for range 3 {
		log.Write(record())
	}

	entries := decode(t, &buffer)
	if len(entries) != 3 {
		t.Fatalf("%d entries, want 3", len(entries))
	}

	for i, entry := range entries {
		seq, _ := entry["seq"].(float64)
		if int(seq) != i+1 {
			t.Errorf("entry %d has seq %v, want %d", i, entry["seq"], i+1)
		}

		if entry["chain"] == nil || entry["chain"] == "" {
			t.Errorf("entry %d has no chain hash", i)
		}
	}

	// Each record's prev must be the previous record's chain hash.
	for i := 1; i < len(entries); i++ {
		if entries[i]["prev"] != entries[i-1]["chain"] {
			t.Errorf("entry %d: prev = %v, want the previous chain %v",
				i, entries[i]["prev"], entries[i-1]["chain"])
		}
	}

	// Verify proves the chain holds, and must reject a record whose
	// contents were changed after the fact.
	if err := audit.Verify(strings.NewReader(buffer.String())); err != nil {
		t.Errorf("Verify rejected an untampered log: %v", err)
	}

	tampered := strings.Replace(buffer.String(), `"reason":"granted"`, `"reason":"denied"`, 1)
	if err := audit.Verify(strings.NewReader(tampered)); err == nil {
		t.Error("Verify accepted a log whose record had been altered")
	}

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	withoutMiddle := strings.Join([]string{lines[0], lines[2]}, "\n")

	if err := audit.Verify(strings.NewReader(withoutMiddle)); err == nil {
		t.Error("Verify accepted a log with a record removed")
	}
}

// The chain must survive concurrent writers: two logins at once must not
// produce two records claiming the same sequence number.
func TestConcurrentWritesKeepTheChainConsistent(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer

	log, err := audit.New(&buffer, audit.Config{Redaction: audit.RedactionFull})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	const writers = 20

	var waiting sync.WaitGroup

	waiting.Add(writers)

	for range writers {
		go func() {
			defer waiting.Done()

			log.Write(record())
		}()
	}

	waiting.Wait()

	entries := decode(t, &buffer)
	if len(entries) != writers {
		t.Fatalf("%d entries, want %d", len(entries), writers)
	}

	seen := make(map[int]bool, writers)

	for _, entry := range entries {
		seq, _ := entry["seq"].(float64)
		if seen[int(seq)] {
			t.Errorf("sequence number %d appears twice", int(seq))
		}

		seen[int(seq)] = true
	}

	if err := audit.Verify(strings.NewReader(buffer.String())); err != nil {
		t.Errorf("the chain does not hold after concurrent writes: %v", err)
	}
}
