// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

package keys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/motrice/smartcard-op/internal/adapters/keys"
)

// writeKey writes a PKCS#8 PEM private key of the given size into dir.
func writeKey(t *testing.T, dir, name string, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name), block, 0o600); err != nil {
		t.Fatalf("could not write key: %v", err)
	}

	return key
}

func TestLoadReadsTheSigningKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	written := writeKey(t, dir, "current.pem", 2048)

	set, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	signing := set.SigningKey()
	if signing.ID() == "" {
		t.Error("the signing key has no key id")
	}

	if got := signing.SignatureAlgorithm(); got != "RS256" {
		t.Errorf("SignatureAlgorithm() = %q, want RS256", got)
	}

	private, ok := signing.Key().(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Key() returned %T, want *rsa.PrivateKey", signing.Key())
	}

	if !private.Equal(written) {
		t.Error("Key() returned a different key than the one written")
	}
}

// The key id must be derived from the key itself, so that the same key always
// gets the same id across restarts and across a two-key rotation window.
func TestLoadDerivesAStableKeyID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "current.pem", 2048)

	first, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	second, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if first.SigningKey().ID() != second.SigningKey().ID() {
		t.Errorf("key id changed between loads: %q then %q",
			first.SigningKey().ID(), second.SigningKey().ID())
	}
}

// This is the most important test in the package. The JWKS is serialised
// straight from what PublicKeys returns, so a type carrying private material
// there would publish the private key at /keys. The types are deliberately
// separate so that it cannot happen, and this test proves the serialised form.
func TestPublicKeysPublishNoPrivateMaterial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "current.pem", 2048)
	writeKey(t, dir, "next.pem", 2048)

	set, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	encoded, err := json.Marshal(set.JSONWebKeySet())
	if err != nil {
		t.Fatalf("could not serialise the key set: %v", err)
	}

	body := string(encoded)
	for _, member := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(body, member) {
			t.Errorf("the key set contains the private member %s: %s", member, body)
		}
	}

	if !strings.Contains(body, `"n"`) || !strings.Contains(body, `"e"`) {
		t.Errorf("the key set lacks the public modulus or exponent: %s", body)
	}
}

// Rotation publishes the next key before it is ever used to sign, so there is
// never a window where a token is signed by a key absent from the key set.
func TestLoadPublishesEveryKeyButSignsWithCurrent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	current := writeKey(t, dir, "current.pem", 2048)
	writeKey(t, dir, "next.pem", 2048)
	writeKey(t, dir, "retired.pem", 2048)

	set, err := keys.Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := len(set.PublicKeys()); got != 3 {
		t.Errorf("%d public keys, want 3", got)
	}

	signing, ok := set.SigningKey().Key().(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Key() returned %T", set.SigningKey().Key())
	}

	if !signing.Equal(current) {
		t.Error("signing uses a key other than current.pem")
	}

	// The signing key must appear in the published set, or a verifier could
	// not fetch the key for a token we just issued.
	var found bool

	for _, public := range set.PublicKeys() {
		if public.ID() == set.SigningKey().ID() {
			found = true
		}

		if public.Use() != "sig" {
			t.Errorf("Use() = %q, want sig", public.Use())
		}
	}

	if !found {
		t.Error("the signing key is absent from the published key set")
	}
}

func TestLoadRejectsUnusableDirectories(t *testing.T) {
	t.Parallel()

	t.Run("no current key", func(t *testing.T) {
		t.Parallel()

		_, err := keys.Load(t.TempDir())
		if !errors.Is(err, keys.ErrNoSigningKey) {
			t.Fatalf("error = %v, want ErrNoSigningKey", err)
		}
	})

	t.Run("directory does not exist", func(t *testing.T) {
		t.Parallel()

		_, err := keys.Load(filepath.Join(t.TempDir(), "absent"))
		if !errors.Is(err, keys.ErrNoSigningKey) {
			t.Fatalf("error = %v, want ErrNoSigningKey", err)
		}
	})

	t.Run("not a pem file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dir, "current.pem"), []byte("just text"), 0o600); err != nil {
			t.Fatalf("could not write file: %v", err)
		}

		_, err := keys.Load(dir)
		if !errors.Is(err, keys.ErrUnusableKey) {
			t.Fatalf("error = %v, want ErrUnusableKey", err)
		}
	})

	// EFOS operates at assurance level 3 and 4. A signing key weaker than the
	// cards it vouches for would be the weakest link in the chain.
	t.Run("key too small", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeKey(t, dir, "current.pem", 1024)

		_, err := keys.Load(dir)
		if !errors.Is(err, keys.ErrUnusableKey) {
			t.Fatalf("error = %v, want ErrUnusableKey", err)
		}
	})
}

// A malformed next.pem must not be ignored. Silently publishing fewer keys
// than the operator intended would break rotation in a way nobody notices
// until tokens start failing to verify.
func TestLoadRejectsAMalformedRotationKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey(t, dir, "current.pem", 2048)

	if err := os.WriteFile(
		filepath.Join(dir, "next.pem"), []byte("not a key"), 0o600); err != nil {
		t.Fatalf("could not write file: %v", err)
	}

	_, err := keys.Load(dir)
	if !errors.Is(err, keys.ErrUnusableKey) {
		t.Fatalf("error = %v, want ErrUnusableKey", err)
	}
}
