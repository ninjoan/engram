package backupcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testKeyBytes(fill byte) []byte { return bytes.Repeat([]byte{fill}, KeySize) }

func mustSealer(t *testing.T, fill byte) *Sealer {
	t.Helper()
	key, err := ParseKey(hex.EncodeToString(testKeyBytes(fill)))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	sealer, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

const testAD = "engram-backup-destination:v1:secret_access_key"

func TestParseKeyAcceptsExactly32BytesInBase64OrHex(t *testing.T) {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = byte(i*7 + 250) // includes bytes that differ between std and url base64
	}
	encodings := map[string]string{
		"hex":        hex.EncodeToString(raw),
		"hex upper":  strings.ToUpper(hex.EncodeToString(raw)),
		"std":        base64.StdEncoding.EncodeToString(raw),
		"url":        base64.URLEncoding.EncodeToString(raw),
		"raw std":    base64.RawStdEncoding.EncodeToString(raw),
		"raw url":    base64.RawURLEncoding.EncodeToString(raw),
		"whitespace": "  " + base64.StdEncoding.EncodeToString(raw) + "\n",
	}
	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			key, err := ParseKey(encoded)
			if err != nil {
				t.Fatalf("ParseKey(%s) error: %v", name, err)
			}
			if !bytes.Equal(key.bytes[:], raw) {
				t.Fatalf("ParseKey(%s) decoded different bytes", name)
			}
		})
	}
}

func TestParseKeyRejectsWrongLengthsAndGarbageWithoutEchoingInput(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"16 hex":     hex.EncodeToString(testKeyBytes(1)[:16]),
		"31 hex":     hex.EncodeToString(testKeyBytes(1)[:31]),
		"33 hex":     hex.EncodeToString(append(testKeyBytes(1), 1)),
		"16 base64":  base64.StdEncoding.EncodeToString(testKeyBytes(2)[:16]),
		"31 base64":  base64.StdEncoding.EncodeToString(testKeyBytes(2)[:31]),
		"33 base64":  base64.StdEncoding.EncodeToString(append(testKeyBytes(2), 2)),
		"garbage":    "not a key at all !!! not a key at all !!!!!",
		"passphrase": "correct horse battery staple",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			key, err := ParseKey(encoded)
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ParseKey error = %v, want %v", err, ErrInvalidKey)
			}
			if key != nil {
				t.Fatalf("ParseKey returned a key for invalid input")
			}
			if encoded != "" && strings.Contains(err.Error(), strings.TrimSpace(encoded)) {
				t.Fatalf("error %q echoes the configured key", err)
			}
			if !strings.Contains(err.Error(), "ENGRAM_CLOUD_BACKUP_KEY") {
				t.Fatalf("error %q does not name the variable", err)
			}
		})
	}
}

func TestKeyNeverFormatsItsBytes(t *testing.T) {
	raw := testKeyBytes(0xab)
	key, err := ParseKey(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	type holder struct{ Key *Key }
	for _, out := range []string{
		fmt.Sprintf("%v %+v %#v %s %x %q", key, key, key, key, key, key),
		fmt.Sprintf("%v %+v %#v", *key, *key, *key),
		fmt.Sprintf("%v %+v %#v", holder{key}, holder{key}, holder{key}),
	} {
		if strings.Contains(out, "abab") || strings.Contains(out, "171 171") || strings.Contains(out, base64.StdEncoding.EncodeToString(raw)[:8]) {
			t.Fatalf("formatted key leaks its bytes: %s", out)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	sealer := mustSealer(t, 1)
	plaintext := []byte("r2-secret-access-key/with+symbols=")
	sealed, err := sealer.Seal(testAD, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(sealed, "v1:"+sealer.Fingerprint()+":") {
		t.Fatalf("sealed value %q lacks the version and key fingerprint", sealed)
	}
	if strings.Contains(sealed, string(plaintext)) {
		t.Fatalf("sealed value contains the plaintext")
	}
	opened, err := sealer.Open(testAD, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open = %q, want %q", opened, plaintext)
	}
}

func TestFingerprintIsFirst8BytesOfKeySHA256(t *testing.T) {
	sealer := mustSealer(t, 1)
	sum := sha256.Sum256(testKeyBytes(1))
	if got, want := sealer.Fingerprint(), hex.EncodeToString(sum[:8]); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	if mustSealer(t, 1).Fingerprint() != sealer.Fingerprint() {
		t.Fatalf("fingerprint is not deterministic")
	}
	if mustSealer(t, 2).Fingerprint() == sealer.Fingerprint() {
		t.Fatalf("different keys share a fingerprint")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	sealer := mustSealer(t, 1)
	sealed, err := sealer.Seal(testAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "v1:" + sealer.Fingerprint() + ":"
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for i := range body {
		flipped := bytes.Clone(body)
		flipped[i] ^= 0x01
		opened, err := sealer.Open(testAD, prefix+base64.RawURLEncoding.EncodeToString(flipped))
		if !errors.Is(err, ErrSealedValueInvalid) {
			t.Fatalf("flip byte %d: Open error = %v, want %v", i, err, ErrSealedValueInvalid)
		}
		if opened != nil {
			t.Fatalf("flip byte %d returned plaintext", i)
		}
	}
	for _, malformed := range []string{"", "v1:", "v2:" + sealer.Fingerprint() + ":AAAA", prefix + "!!!", prefix + "AAAA", "v1:" + sealer.Fingerprint()} {
		if _, err := sealer.Open(testAD, malformed); !errors.Is(err, ErrSealedValueInvalid) {
			t.Errorf("Open(%q) error = %v, want %v", malformed, err, ErrSealedValueInvalid)
		}
	}
}

func TestOpenWithWrongKeyReportsKeyMismatch(t *testing.T) {
	sealed, err := mustSealer(t, 1).Seal(testAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := mustSealer(t, 2).Open(testAD, sealed)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("Open error = %v, want %v", err, ErrKeyMismatch)
	}
	if !strings.Contains(err.Error(), "backup destination key does not match") {
		t.Fatalf("error %q is not the documented mismatch message", err)
	}
	if opened != nil {
		t.Fatalf("wrong key returned plaintext")
	}
}

func TestOpenRejectsAssociatedDataMismatch(t *testing.T) {
	sealer := mustSealer(t, 1)
	sealed, err := sealer.Seal(testAD, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sealer.Open("engram-backup-destination:v1:access_key_id", sealed)
	if !errors.Is(err, ErrSealedValueInvalid) {
		t.Fatalf("Open error = %v, want %v", err, ErrSealedValueInvalid)
	}
	if opened != nil {
		t.Fatalf("AD mismatch returned plaintext")
	}
}

func TestSealUsesAFreshNonceEverySeal(t *testing.T) {
	sealer := mustSealer(t, 1)
	seen := map[string]bool{}
	nonces := map[string]bool{}
	prefix := "v1:" + sealer.Fingerprint() + ":"
	for range 64 {
		sealed, err := sealer.Seal(testAD, []byte("same plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[sealed] {
			t.Fatalf("Seal repeated a ciphertext")
		}
		seen[sealed] = true
		body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(body[:NonceSize])
		if nonces[nonce] {
			t.Fatalf("Seal repeated a nonce")
		}
		nonces[nonce] = true
	}
}

func TestNewSealerRejectsNilKey(t *testing.T) {
	if _, err := NewSealer(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewSealer(nil) error = %v, want %v", err, ErrInvalidKey)
	}
}
