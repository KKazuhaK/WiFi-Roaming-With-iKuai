package secret

import (
	"errors"
	"strings"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRoundTrip(t *testing.T) {
	k := NewKeyring(testKey)
	for _, plain := range []string{
		"hunter2",
		"",
		strings.Repeat("x", 4096), // A long client secret must not be truncated anywhere.
		"unicode 密钥 🔐",
	} {
		enc, err := k.Encrypt(plain)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plain, err)
		}
		got, err := k.Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt of %q: %v", plain, err)
		}
		if got != plain {
			t.Errorf("round trip of %q gave %q", plain, got)
		}
	}
}

// Pins the documented cost of Encrypt's idempotency rule: a plaintext that
// itself starts with the prefix is passed through and then read back as
// ciphertext, so it fails. This is a limitation, not a bug — the test exists so
// that anyone who makes a secret settable that could look like this finds out
// here rather than in production.
func TestPlaintextLookingLikeCiphertextIsUnrepresentable(t *testing.T) {
	k := NewKeyring(testKey)
	const lookalike = Prefix + "not-really-encrypted-just-looks-like-it"

	stored, err := k.Encrypt(lookalike)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if stored != lookalike {
		t.Fatalf("Encrypt should pass a prefixed value through, got %q", stored)
	}
	if _, err := k.Decrypt(stored); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Decrypt = %v, want ErrCorrupt — if this now round-trips, the idempotency rule changed and the doc comment is stale", err)
	}
}

func TestEncryptSkipsEmptyAndAlreadyEncrypted(t *testing.T) {
	k := NewKeyring(testKey)

	// An unset credential must stay visibly unset rather than becoming an
	// opaque blob that looks configured.
	if got, _ := k.Encrypt(""); got != "" {
		t.Errorf("Encrypt(\"\") = %q, want empty", got)
	}

	// The settings form round-trips values it did not change. Encrypting an
	// already-encrypted value would nest it, and the next read would hand the
	// caller an inner "enc:v1:..." string.
	once, err := k.Encrypt("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := k.Encrypt(once)
	if err != nil {
		t.Fatal(err)
	}
	if twice != once {
		t.Error("re-encrypting an encrypted value changed it; double encryption")
	}
}

func TestCiphertextIsNondeterministic(t *testing.T) {
	k := NewKeyring(testKey)
	a, _ := k.Encrypt("hunter2")
	b, _ := k.Encrypt("hunter2")
	if a == b {
		t.Error("identical plaintexts produced identical ciphertexts; the nonce is not random")
	}
	// Both must still decrypt.
	for _, c := range []string{a, b} {
		if got, err := k.Decrypt(c); err != nil || got != "hunter2" {
			t.Errorf("Decrypt(%q) = (%q, %v)", c, got, err)
		}
	}
}

func TestPlaintextNeverAppearsInCiphertext(t *testing.T) {
	k := NewKeyring(testKey)
	enc, _ := k.Encrypt("super-secret-tenant-value")
	if strings.Contains(enc, "super-secret") {
		t.Fatalf("plaintext leaked into the stored form: %q", enc)
	}
	if !strings.HasPrefix(enc, Prefix) {
		t.Errorf("stored form %q lacks the %q prefix", enc, Prefix)
	}
}

// An installation that has not set encryption_key must keep working — refusing
// would strand every existing deployment on upgrade.
func TestNoKeyStoresPlaintext(t *testing.T) {
	k := NewKeyring("")
	if k.Enabled() {
		t.Fatal("empty material must not produce an enabled keyring")
	}
	enc, err := k.Encrypt("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if enc != "hunter2" {
		t.Errorf("without a key, Encrypt should pass through, got %q", enc)
	}
	got, err := k.Decrypt("hunter2")
	if err != nil || got != "hunter2" {
		t.Errorf("Decrypt of a plaintext value = (%q, %v)", got, err)
	}
}

// The dangerous case: the database holds ciphertext and the process lost its
// key. Returning the blob would hand an OIDC client "enc:v1:..." as its secret
// and produce an auth failure with no connection to the real cause.
func TestNoKeyRefusesEncryptedValue(t *testing.T) {
	withKey := NewKeyring(testKey)
	enc, _ := withKey.Encrypt("hunter2")

	noKey := NewKeyring("")
	got, err := noKey.Decrypt(enc)
	if !errors.Is(err, ErrNoKey) {
		t.Errorf("Decrypt without a key = (%q, %v), want ErrNoKey", got, err)
	}
	if got != "" {
		t.Errorf("failed decryption returned %q; it must return empty, never the raw blob", got)
	}
}

func TestWrongKeyIsReportedAsCorrupt(t *testing.T) {
	enc, _ := NewKeyring(testKey).Encrypt("hunter2")
	other := NewKeyring("ffffffffffffffffffffffffffffffffffffffffffffffff")

	got, err := other.Decrypt(enc)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("Decrypt with the wrong key = (%q, %v), want ErrCorrupt", got, err)
	}
	if got != "" {
		t.Errorf("failed decryption returned %q, want empty", got)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	k := NewKeyring(testKey)
	enc, _ := k.Encrypt("hunter2")

	// Flip a character in the base64 body. GCM's tag must catch it.
	body := []byte(strings.TrimPrefix(enc, Prefix))
	for i := range body {
		if body[i] != 'A' {
			body[i] = 'A'
			break
		}
	}
	if _, err := k.Decrypt(Prefix + string(body)); err == nil {
		t.Error("tampered ciphertext decrypted without error")
	}

	// Truncation below the nonce length must not panic.
	if _, err := k.Decrypt(Prefix + "AAAA"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated ciphertext gave %v, want ErrCorrupt", err)
	}
	// Non-base64 body.
	if _, err := k.Decrypt(Prefix + "!!!not base64!!!"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("invalid base64 gave %v, want ErrCorrupt", err)
	}
}

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("hunter2") {
		t.Error("plaintext reported as encrypted")
	}
	enc, _ := NewKeyring(testKey).Encrypt("hunter2")
	if !IsEncrypted(enc) {
		t.Error("encrypted value not recognised")
	}
}

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"abc":               "********",
		"abcdefgh":          "********efgh",
		"a-long-secret-xyz": "********-xyz",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
	// Whatever the rule, the leading characters of a real secret must never
	// show — those are the ones that narrow a brute-force search.
	if got := Mask("hunter2-with-more-text"); strings.Contains(got, "hunter") {
		t.Errorf("Mask leaked the start of the secret: %q", got)
	}
}
