package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The claim the whole storage migration rests on: a single-use code can be
// redeemed exactly once, even when several store instances sharing a database
// race for it.
//
// The file-backed store passed the single-process version of this on a mutex and
// would have failed the moment a second process existed — each held its own map,
// so both would have seen an unused code and both would have let a device onto
// the network. Separate GuestCodeStore values over one database is the closest
// in-process model of that, and it exercises the same transaction and row lock
// the real deployment relies on.
func TestValidateRedeemsSingleUseCodeExactlyOnce(t *testing.T) {
	db := testDB(t)

	writer := newGuestCodeStore(db)
	if !writer.Add(&GuestCode{Code: "onceonly", CreatedAt: time.Now(), MaxUses: 1, DurationMin: 60}) {
		t.Fatal("setup: Add returned false")
	}

	const racers = 16
	// One store per goroutine, standing in for one process each.
	stores := make([]*GuestCodeStore, racers)
	for i := range stores {
		stores[i] = newGuestCodeStore(db)
	}

	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(s *GuestCodeStore, n int) {
			defer wg.Done()
			<-start
			if got := s.Validate("onceonly", "mac", "ip", "guest"); got != nil {
				atomic.AddInt64(&wins, 1)
			}
		}(stores[i], i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&wins); got != 1 {
		t.Errorf("%d of %d racers redeemed a single-use code; exactly 1 must win", got, racers)
	}

	// And the ledger has to agree with the outcome — one accepted redemption
	// means one recorded use, or the audit trail lies about who got on.
	final := writer.Get("onceonly")
	if final == nil {
		t.Fatal("the code disappeared")
	}
	if len(final.Uses) != 1 {
		t.Errorf("%d uses recorded, want 1", len(final.Uses))
	}
}

// A multi-use code must admit exactly MaxUses devices under the same race, not
// "roughly MaxUses".
func TestValidateHonoursMaxUsesUnderContention(t *testing.T) {
	db := testDB(t)
	const maxUses = 3

	if !newGuestCodeStore(db).Add(&GuestCode{
		Code: "threeuses", CreatedAt: time.Now(), MaxUses: maxUses, DurationMin: 60,
	}) {
		t.Fatal("setup: Add returned false")
	}

	const racers = 20
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := newGuestCodeStore(db)
			<-start
			if got := s.Validate("threeuses", "mac", "ip", "guest"); got != nil {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&wins); got != maxUses {
		t.Errorf("%d racers admitted, want exactly %d", got, maxUses)
	}
}

// Add is the other place a race could hand out the same code twice: two
// instances generating codes concurrently must not both believe they created it.
func TestAddIsExclusiveUnderContention(t *testing.T) {
	db := testDB(t)

	const racers = 12
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := newGuestCodeStore(db)
			<-start
			if s.Add(&GuestCode{Code: "collide", CreatedAt: time.Now(), DurationMin: 60}) {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&wins); got != 1 {
		t.Errorf("%d racers reported creating the same code; exactly 1 must win", got)
	}
}

// An expired code must be refused even if it still has uses left, and the
// refusal must not record a use.
func TestValidateRefusesExpiredCode(t *testing.T) {
	db := testDB(t)
	s := newGuestCodeStore(db)
	if !s.Add(&GuestCode{
		Code: "expiredcode", CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), MaxUses: 5,
	}) {
		t.Fatal("setup: Add returned false")
	}

	if got := s.Validate("expiredcode", "mac", "ip", "guest"); got != nil {
		t.Error("an expired code was redeemed")
	}
	if c := s.Get("expiredcode"); c == nil || len(c.Uses) != 0 {
		t.Errorf("a refused redemption recorded a use: %+v", c)
	}
}

// Case and surrounding whitespace must not matter — guests type these off a
// printed slip — and that has to hold identically on every backend, which is
// why the lookup key is an explicit column rather than a collation assumption.
func TestValidateIsCaseAndWhitespaceInsensitive(t *testing.T) {
	db := testDB(t)
	s := newGuestCodeStore(db)
	if !s.Add(&GuestCode{Code: "MixedCase99", CreatedAt: time.Now(), MaxUses: 3, DurationMin: 60}) {
		t.Fatal("setup: Add returned false")
	}

	for _, typed := range []string{"mixedcase99", "MIXEDCASE99", "  MixedCase99  "} {
		if got := s.Validate(typed, "mac", "ip", "guest"); got == nil {
			t.Errorf("Validate(%q) was refused", typed)
		} else if got.Code != "MixedCase99" {
			// The stored spelling is what the admin sees; redemption must not
			// rewrite it to whatever the guest typed.
			t.Errorf("Validate(%q) returned code %q, want the stored spelling", typed, got.Code)
		}
	}

	// A differently-cased duplicate must be refused, or two admins could create
	// two codes that redeem as one.
	if s.Add(&GuestCode{Code: "MIXEDCASE99", CreatedAt: time.Now()}) {
		t.Error("a case-variant duplicate was accepted")
	}
}
