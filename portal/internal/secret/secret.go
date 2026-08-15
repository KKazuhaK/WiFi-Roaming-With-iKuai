// Package secret encrypts the credentials the portal keeps in its database.
//
// Moving settings out of .env and into the database means the OIDC client
// secret, the iKuai app key and the Duo keys stop living in a 0600 file on one
// machine and start living somewhere that gets backed up, replicated, and read
// by whoever has database access. Encrypting them at rest is what makes that
// trade acceptable: a leaked database dump, a snapshot on a decommissioned
// disk, or a read-only replica handed to an analytics tool yields ciphertext.
//
// It is emphatically not protection against an attacker who already has the
// portal's own filesystem — the key sits in the bootstrap config file that the
// process reads at startup. The threat it addresses is the database being a
// second, wider-reaching copy of the secrets, and that is a real threat: the
// .env file never travelled to a managed MySQL provider.
//
// Format: "enc:v1:" + base64(nonce || ciphertext || tag), AES-256-GCM.
// The version tag is there so a future key rotation or algorithm change can be
// distinguished on read instead of guessed.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Prefix marks an encrypted value. Anything without it is stored plaintext,
// which is how a value written before a key was configured stays readable.
const Prefix = "enc:v1:"

// ErrNoKey is returned when decryption is attempted without a configured key.
var ErrNoKey = errors.New("secret: no encryption key configured")

// ErrCorrupt means the stored value carries the prefix but failed to decrypt.
// The usual cause is a changed or lost encryption_key, and the usual fix is
// re-entering the affected credential — so callers should surface it as a
// configuration problem, not an internal error.
var ErrCorrupt = errors.New("secret: value cannot be decrypted (wrong or lost encryption key?)")

// Keyring holds the derived key. A value type rather than a package-level
// variable so tests, and any future per-tenant key, do not have to fight global
// state.
type Keyring struct {
	key []byte
}

// NewKeyring derives an AES-256 key from arbitrary key material.
//
// SHA-256 rather than a password KDF (scrypt/argon2) on purpose. The material
// is a machine-generated 48+ character random string from the bootstrap config,
// not a human-chosen password, so there is no low-entropy input for a slow KDF
// to defend. Making startup take a second to stretch a key that was already
// uniformly random would buy nothing.
//
// Empty material yields a keyring that stores plaintext. That is the documented
// behaviour for a deployment that has not set encryption_key yet — refusing to
// start would strand every existing installation on upgrade — and the caller is
// expected to log loudly about it.
func NewKeyring(material string) *Keyring {
	material = strings.TrimSpace(material)
	if material == "" {
		return &Keyring{}
	}
	sum := sha256.Sum256([]byte(material))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return &Keyring{key: key}
}

// Enabled reports whether encryption is active.
func (k *Keyring) Enabled() bool { return len(k.key) > 0 }

// Encrypt returns the storable form of plaintext.
//
// Two values pass through untouched: the empty string, because an unset
// credential should stay visibly unset rather than becoming an opaque blob; and
// anything already carrying Prefix, so that re-saving a settings form that
// round-tripped an encrypted value does not double-encrypt it.
//
// The second rule has a known cost: a plaintext that itself begins with
// "enc:v1:" cannot be stored, because Decrypt will later mistake it for
// ciphertext and fail. That is accepted rather than worked around — defensive
// idempotency protects every present and future caller from nesting, while the
// unrepresentable input is a string no credential this portal handles can take
// (OIDC secrets, iKuai app keys and Duo keys are all opaque tokens without
// colon-delimited prefixes). If a settable secret ever could look like that,
// this rule has to be replaced by the caller tracking encrypted-ness itself,
// not by loosening the check.
func (k *Keyring) Encrypt(plaintext string) (string, error) {
	if plaintext == "" || strings.HasPrefix(plaintext, Prefix) {
		return plaintext, nil
	}
	if !k.Enabled() {
		return plaintext, nil
	}
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return "", fmt.Errorf("secret: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("secret: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret: nonce: %w", err)
	}
	// Seal appends to its first argument, so passing the nonce prefixes it to
	// the output — GCM nonces are not secret and must be stored alongside.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return Prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. A value without Prefix is returned as-is, which is
// what makes a database written before encryption was configured still readable.
func (k *Keyring) Decrypt(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, Prefix) {
		return stored, nil
	}
	if !k.Enabled() {
		// The database holds ciphertext and the process has no key. Silently
		// returning the blob would hand an OIDC client an "enc:v1:..." secret
		// and produce a baffling auth failure three layers away.
		return "", ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", ErrCorrupt
	}
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return "", fmt.Errorf("secret: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("secret: gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrCorrupt
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// GCM authentication failure. Almost always a rotated or lost key
		// rather than tampering, but the two are indistinguishable here by
		// design, so report the actionable one.
		return "", ErrCorrupt
	}
	return string(plain), nil
}

// IsEncrypted reports whether a stored value is in encrypted form. Used by the
// settings layer to decide whether a value needs re-encrypting after a key is
// configured for the first time.
func IsEncrypted(stored string) bool {
	return strings.HasPrefix(stored, Prefix)
}

// Mask renders a secret for display. The admin API never returns a stored
// credential — it returns a has_* boolean — but a few places (the CLI's
// `config get`, startup diagnostics) need to show that something is set without
// showing what.
func Mask(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	// Fewer than 8 characters means any suffix is a large fraction of the
	// secret, so show nothing.
	if len(plaintext) < 8 {
		return "********"
	}
	return "********" + plaintext[len(plaintext)-4:]
}
