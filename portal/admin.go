package main

// admin.go
// Guest-code domain model and random generation.
//
// Storage moved to the database; see store_guestcode.go. What stays here is the
// record type, the predicates the rest of the portal reasons with (expired,
// exhausted, active), and code generation — none of which depend on where the
// rows live.

import (
	"crypto/rand"
	"math/big"
	"time"
)

// GuestCodeType is the selectable character set for batch generation.
type GuestCodeType string

const (
	CodeNumeric      GuestCodeType = "numeric"
	CodeAlpha        GuestCodeType = "alpha"
	CodeAlphaNumeric GuestCodeType = "alphanumeric"
)

// GuestCode is a single guest-code record.
// Design notes:
//   - ExpiresAt is an absolute expiration time. Zero means never expires.
//   - DurationMin is the iKuai allow-list duration after each successful use. 0 means unlimited.
//   - MaxUses limits how many successful uses the same code allows. 0 means unlimited.
//   - Note is an admin note and is only shown in the admin UI.
type GuestCode struct {
	Code        string    `json:"code"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	DurationMin int       `json:"duration_min"`
	MaxUses     int       `json:"max_uses,omitempty"`
	Note        string    `json:"note,omitempty"`
	Uses        []CodeUse `json:"uses,omitempty"`
}

type CodeUse struct {
	At       time.Time `json:"at"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	GuestUPN string    `json:"guest_upn"` // e.g. Guest-abc12345
}

func (c *GuestCode) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// IsExhausted reports whether MaxUses has been reached (MaxUses=0 means unlimited).
func (c *GuestCode) IsExhausted() bool {
	return c.MaxUses > 0 && len(c.Uses) >= c.MaxUses
}

func (c *GuestCode) UseCount() int {
	return len(c.Uses)
}

// Status is used by the UI tabs. Any code used at least once is "used"; exhausted vs partially
// used is handled by IsActive. This keeps the existing admin.html tabs unchanged.
func (c *GuestCode) Status() string {
	switch {
	case c.IsExpired():
		return "expired"
	case len(c.Uses) > 0:
		return "used"
	default:
		return "unused"
	}
}

// IsActive reports whether the code can still be used now: not expired and not exhausted.
// This is distinct from Status: Status is for UI grouping, while IsActive drives business
// decisions such as DeleteInactive. C3 depends on partially used multi-use codes staying active.
func (c *GuestCode) IsActive() bool {
	return !c.IsExpired() && !c.IsExhausted()
}

// --- Random code generation ---

func generateCode(codeType GuestCodeType, length int) (string, error) {
	if length < 4 {
		length = 4
	}
	if length > 64 {
		length = 64
	}
	var alphabet string
	switch codeType {
	case CodeAlpha:
		alphabet = "abcdefghijklmnopqrstuvwxyz"
	case CodeAlphaNumeric:
		alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	case CodeNumeric:
		fallthrough
	default:
		alphabet = "0123456789"
	}
	buf := make([]byte, length)
	maxIdx := big.NewInt(int64(len(alphabet)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}
