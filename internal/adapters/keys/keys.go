// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package keys loads the provider's signing keys and publishes their public
// halves.
//
// The private and the public key are deliberately separate types. The JWKS is
// serialised straight from what PublicKeys returns, so a single type carrying
// both halves would be one mistaken return away from publishing the private key
// at the /keys endpoint. Making that structurally impossible is cheaper than
// remembering not to do it.
package keys

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	// ErrNoSigningKey means no usable current.pem was found. The service
	// must refuse to start rather than generate a key of its own: a restart
	// would then silently invalidate every token in flight and the key's
	// provenance would be lost from the audit trail.
	ErrNoSigningKey = errors.New("no signing key")
	// ErrUnusableKey means a key file was present but cannot be used.
	ErrUnusableKey = errors.New("unusable key")
)

const (
	// algorithm is the only signature algorithm we issue with. RS256 gives
	// the widest interoperability with every verifier Zitadel might use;
	// ES256 would work too but buys nothing here.
	algorithm = jose.RS256
	// minimumKeySize is the smallest signing key accepted. EFOS cards are
	// 2048-bit and operate at assurance level 3 and 4, so a weaker signing
	// key would be the weakest link in the chain. 3072 is recommended for a
	// government deployment; 2048 is the floor.
	minimumKeySize = 2048
	// keyUse is the JWK "use" value for a signature key.
	keyUse = "sig"

	currentFile = "current.pem"
	nextFile    = "next.pem"
	retiredFile = "retired.pem"
)

// SigningKey is the private key tokens are signed with. It satisfies
// op.SigningKey structurally.
type SigningKey struct {
	private *rsa.PrivateKey
	id      string
}

// SignatureAlgorithm reports the algorithm tokens are signed with.
func (s *SigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return algorithm }

// Key returns the private key. Only the token signer may call this.
func (s *SigningKey) Key() any { return s.private }

// ID returns the key identifier that goes into the token header.
func (s *SigningKey) ID() string { return s.id }

// PublicKey is a published verification key. It satisfies op.Key structurally.
//
// It holds no private material, and there is no way to obtain any from it.
type PublicKey struct {
	public *rsa.PublicKey
	id     string
}

// ID returns the key identifier verifiers match against a token header.
func (p *PublicKey) ID() string { return p.id }

// Algorithm reports the algorithm the key verifies.
func (p *PublicKey) Algorithm() jose.SignatureAlgorithm { return algorithm }

// Use reports the JWK use, which is always signature.
func (p *PublicKey) Use() string { return keyUse }

// Key returns the public key.
func (p *PublicKey) Key() any { return p.public }

// Set is the provider's key material: one key to sign with and every key
// verifiers should accept.
type Set struct {
	signing *SigningKey
	public  []*PublicKey
}

// Load reads the key material from a directory, as mounted from a Kubernetes
// secret.
//
//   - current.pem is required and is the key tokens are signed with.
//   - next.pem is optional and is published without being used, so that a new
//     key is known to every verifier before it is first used to sign.
//   - retired.pem is optional and is published so that tokens still in flight
//     after a rotation can be verified.
//
// A key file that is present but malformed is an error, never a silent
// omission: publishing fewer keys than the operator intended would break
// rotation in a way nobody notices until tokens start failing to verify.
func Load(dir string) (*Set, error) {
	current, err := loadPrivateKey(filepath.Join(dir, currentFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s holds no %s", ErrNoSigningKey, dir, currentFile)
		}

		return nil, err
	}

	set := &Set{}

	id, err := thumbprint(current)
	if err != nil {
		return nil, err
	}

	set.signing = &SigningKey{private: current, id: id}
	set.public = append(set.public, &PublicKey{public: &current.PublicKey, id: id})

	for _, name := range []string{nextFile, retiredFile} {
		extra, err := loadPrivateKey(filepath.Join(dir, name))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return nil, err
		}

		extraID, err := thumbprint(extra)
		if err != nil {
			return nil, err
		}

		set.public = append(set.public, &PublicKey{public: &extra.PublicKey, id: extraID})
	}

	return set, nil
}

// SigningKey returns the key tokens are signed with.
func (s *Set) SigningKey() *SigningKey { return s.signing }

// PublicKeys returns every key verifiers should accept, the signing key
// included.
func (s *Set) PublicKeys() []*PublicKey { return s.public }

// JSONWebKeySet renders the published keys as a JWKS, which is what the /keys
// endpoint serves.
func (s *Set) JSONWebKeySet() jose.JSONWebKeySet {
	webKeys := make([]jose.JSONWebKey, 0, len(s.public))

	for _, key := range s.public {
		webKeys = append(webKeys, jose.JSONWebKey{
			Key:       key.public,
			KeyID:     key.id,
			Algorithm: string(algorithm),
			Use:       keyUse,
		})
	}

	return jose.JSONWebKeySet{Keys: webKeys}
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	// The path is assembled from the operator-supplied key directory, not
	// from anything a request carries, and the service must be able to read
	// keys from wherever they are mounted.
	raw, err := os.ReadFile(path) //nolint:gosec // operator configuration, never request input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: %s: %w", ErrUnusableKey, path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %s is not PEM", ErrUnusableKey, path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a PKCS#8 private key: %w",
			ErrUnusableKey, path, err)
	}

	key, isRSA := parsed.(*rsa.PrivateKey)
	if !isRSA {
		return nil, fmt.Errorf("%w: %s holds a %T, want an RSA key for %s",
			ErrUnusableKey, path, parsed, algorithm)
	}

	if bits := key.N.BitLen(); bits < minimumKeySize {
		return nil, fmt.Errorf("%w: %s is %d bits, at least %d is required",
			ErrUnusableKey, path, bits, minimumKeySize)
	}

	return key, nil
}

// thumbprint derives the key identifier as an RFC 7638 JWK thumbprint. Being
// derived from the key itself, the same key always gets the same identifier —
// across restarts and across a rotation window where two keys are published.
func thumbprint(key *rsa.PrivateKey) (string, error) {
	webKey := jose.JSONWebKey{Key: &key.PublicKey}

	sum, err := webKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: could not derive a key id: %w", ErrUnusableKey, err)
	}

	return base64.RawURLEncoding.EncodeToString(sum), nil
}
