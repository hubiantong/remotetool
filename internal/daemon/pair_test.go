package daemon

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/identity"
)

func newTestPairService(t *testing.T) *PairService {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	store, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewPairService(id, store, log)
}

// otherCode returns a 6-digit code different from code.
func otherCode(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func TestWrongCodeAttempts(t *testing.T) {
	ps := newTestPairService(t)
	if _, _, err := ps.CreateInvite(); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	code, _, ok := ps.CurrentInvite()
	if !ok {
		t.Fatal("expected pending invite")
	}
	key := "attacker"
	now := time.Now()
	for i := 0; i < maxInviteAttempts-1; i++ {
		now = now.Add(time.Minute) // stay outside the backoff window
		if _, err := ps.checkRequest(key, otherCode(code), now); !errors.Is(err, errPairingFailed) {
			t.Fatalf("wrong attempt %d: expected errPairingFailed, got %v", i+1, err)
		}
	}
	if _, _, ok := ps.CurrentInvite(); !ok {
		t.Fatal("invite should survive 4 wrong attempts")
	}
	now = now.Add(time.Minute)
	if _, err := ps.checkRequest(key, otherCode(code), now); !errors.Is(err, errPairingFailed) {
		t.Fatalf("wrong attempt 5: expected errPairingFailed, got %v", err)
	}
	if _, _, ok := ps.CurrentInvite(); ok {
		t.Fatal("invite should be invalidated after 5 wrong attempts")
	}
	// Even the correct code fails now: there is no invite left.
	if inv, err := ps.checkRequest(key, code, now.Add(time.Minute)); err == nil || inv != nil {
		t.Fatalf("expected failure after invalidation, got inv=%v err=%v", inv, err)
	}
}

func TestBackoff(t *testing.T) {
	old := backoffBase
	backoffBase = 10 * time.Millisecond
	defer func() { backoffBase = old }()

	ps := newTestPairService(t)
	if _, _, err := ps.CreateInvite(); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	code, _, ok := ps.CurrentInvite()
	if !ok {
		t.Fatal("expected pending invite")
	}
	key := "attacker"
	now := time.Now()
	if _, err := ps.checkRequest(key, otherCode(code), now); !errors.Is(err, errPairingFailed) {
		t.Fatalf("expected errPairingFailed on wrong code, got %v", err)
	}
	// Still inside the backoff window: even the correct code is rejected.
	if _, err := ps.checkRequest(key, code, now); !errors.Is(err, errPairingFailed) {
		t.Fatalf("expected backoff rejection with correct code, got %v", err)
	}
	time.Sleep(3 * backoffBase)
	if _, err := ps.checkRequest(key, code, time.Now()); err != nil {
		t.Fatalf("expected correct code to proceed after backoff, got %v", err)
	}
}

func TestUnifiedError(t *testing.T) {
	ps := newTestPairService(t)
	key := "prober"
	// No pending invite.
	_, errNoInvite := ps.checkRequest(key, "123456", time.Now())
	// Pending invite, wrong code.
	if _, _, err := ps.CreateInvite(); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	code, _, ok := ps.CurrentInvite()
	if !ok {
		t.Fatal("expected pending invite")
	}
	_, errWrongCode := ps.checkRequest(key, otherCode(code), time.Now().Add(time.Minute))
	if !errors.Is(errNoInvite, errPairingFailed) || !errors.Is(errWrongCode, errPairingFailed) {
		t.Fatalf("expected errPairingFailed, got %v / %v", errNoInvite, errWrongCode)
	}
	if errNoInvite.Error() != errWrongCode.Error() {
		t.Fatalf("failure messages differ: %q vs %q", errNoInvite.Error(), errWrongCode.Error())
	}
}

func TestTokenBucket(t *testing.T) {
	tb := newTokenBucket()
	base := time.Now()
	for i := 0; i < unpairedBurst; i++ {
		if !tb.allow(base) {
			t.Fatalf("token %d/%d refused within burst", i+1, unpairedBurst)
		}
	}
	if tb.allow(base) {
		t.Fatal("bucket should be exhausted after the burst")
	}
	// 200ms at 10 tokens/s refills exactly 2 tokens (synthetic clock).
	refilled := base.Add(200 * time.Millisecond)
	if !tb.allow(refilled) {
		t.Fatal("expected first refilled token to be allowed")
	}
	if !tb.allow(refilled) {
		t.Fatal("expected second refilled token to be allowed")
	}
	if tb.allow(refilled) {
		t.Fatal("expected bucket to be empty after 2 refilled tokens")
	}
}
