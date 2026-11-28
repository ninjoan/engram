// Package backupcrypto seals backup destination credentials at rest with
// AES-256-GCM under the dedicated ENGRAM_CLOUD_BACKUP_KEY.
//
// A sealed value has the form "v1:<fingerprint>:<base64url(nonce||ciphertext)>".
// The fingerprint (first 8 bytes of SHA-256 of the key, hex) lets a wrong or
// rotated key fail with ErrKeyMismatch instead of a generic authentication
// error. Associated data binds every value to its purpose so a ciphertext
// cannot be moved to another field or destination.
package backupcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// KeySize is the exact decoded length of ENGRAM_CLOUD_BACKUP_KEY.
	KeySize = 32
	// NonceSize is the random GCM nonce length prepended to each ciphertext.
	NonceSize = 12

	sealedVersion = "v1"
)

var (
	ErrInvalidKey         = errors.New("backupcrypto: ENGRAM_CLOUD_BACKUP_KEY must be exactly 32 bytes encoded as base64 or hex")
	ErrKeyMismatch        = errors.New("backupcrypto: backup destination key does not match the key that sealed the stored credentials")
	ErrSealedValueInvalid = errors.New("backupcrypto: sealed backup destination value is malformed or was tampered with")
)

// Key is a parsed ENGRAM_CLOUD_BACKUP_KEY. It never formats its bytes, so a
// Config holding it can be printed or logged without leaking the key.
type Key struct {
	bytes [KeySize]byte
}

// Format prints a redacted placeholder for every fmt verb.
func (k Key) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "backupcrypto.Key(redacted)")
}

// ParseKey decodes a 32-byte key from hex or base64 (standard or URL
// alphabet, padded or not). Errors never echo the input.
func ParseKey(encoded string) (*Key, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, ErrInvalidKey
	}
	candidates := make([][]byte, 0, 5)
	if raw, err := hex.DecodeString(encoded); err == nil {
		candidates = append(candidates, raw)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if raw, err := encoding.DecodeString(encoded); err == nil {
			candidates = append(candidates, raw)
		}
	}
	for _, raw := range candidates {
		if len(raw) == KeySize {
			key := &Key{}
			copy(key.bytes[:], raw)
			clear(raw)
			return key, nil
		}
		clear(raw)
	}
	return nil, ErrInvalidKey
}

// Sealer seals and opens values with one key.
type Sealer struct {
	aead        cipher.AEAD
	fingerprint string
}

// NewSealer builds an AES-256-GCM sealer for key.
func NewSealer(key *Key) (*Sealer, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key.bytes[:])
	if err != nil {
		return nil, fmt.Errorf("backupcrypto: init cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, fmt.Errorf("backupcrypto: init gcm: %w", err)
	}
	sum := sha256.Sum256(key.bytes[:])
	return &Sealer{aead: aead, fingerprint: hex.EncodeToString(sum[:8])}, nil
}

// Fingerprint identifies the key without revealing it.
func (s *Sealer) Fingerprint() string {
	return s.fingerprint
}

// Seal encrypts plaintext under a fresh random nonce, bound to associatedData.
func (s *Sealer) Seal(associatedData string, plaintext []byte) (string, error) {
	nonce := make([]byte, NonceSize, NonceSize+len(plaintext)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("backupcrypto: read nonce: %w", err)
	}
	body := s.aead.Seal(nonce, nonce, plaintext, []byte(associatedData))
	return sealedVersion + ":" + s.fingerprint + ":" + base64.RawURLEncoding.EncodeToString(body), nil
}

// Open decrypts a value produced by Seal with the same key and associated
// data. A value sealed by another key fails with ErrKeyMismatch; any other
// failure is ErrSealedValueInvalid.
func (s *Sealer) Open(associatedData, sealed string) ([]byte, error) {
	version, rest, ok := strings.Cut(sealed, ":")
	if !ok || version != sealedVersion {
		return nil, ErrSealedValueInvalid
	}
	fingerprint, encoded, ok := strings.Cut(rest, ":")
	if !ok {
		return nil, ErrSealedValueInvalid
	}
	if fingerprint != s.fingerprint {
		return nil, ErrKeyMismatch
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(body) < NonceSize+s.aead.Overhead() {
		return nil, ErrSealedValueInvalid
	}
	plaintext, err := s.aead.Open(nil, body[:NonceSize], body[NonceSize:], []byte(associatedData))
	if err != nil {
		return nil, ErrSealedValueInvalid
	}
	return plaintext, nil
}
