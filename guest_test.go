package main

import (
	"testing"
	"time"
)

func TestReplayWindowAcceptsForwardProgress(t *testing.T) {
	var w replayWindow
	for seq := uint64(1); seq <= 200; seq++ {
		if !w.accept(seq) {
			t.Fatalf("counter %d should have been accepted", seq)
		}
	}
}

func TestReplayWindowRejectsRepeats(t *testing.T) {
	var w replayWindow
	if !w.accept(7) {
		t.Fatal("first sighting of 7 should be accepted")
	}
	if w.accept(7) {
		t.Fatal("counter 7 was replayed and must be refused")
	}
	if !w.accept(8) {
		t.Fatal("8 is still new and should be accepted")
	}
	if w.accept(8) {
		t.Fatal("counter 8 was replayed and must be refused")
	}
}

// The guest page fires typing and message frames concurrently, so frames can
// legitimately arrive out of order. Anything inside the window is fine; only
// reuse is not.
func TestReplayWindowAllowsOutOfOrderWithinWindow(t *testing.T) {
	var w replayWindow
	for _, seq := range []uint64{1, 2, 3, 10} {
		if !w.accept(seq) {
			t.Fatalf("counter %d should have been accepted", seq)
		}
	}
	for _, seq := range []uint64{4, 5, 9} {
		if !w.accept(seq) {
			t.Fatalf("late but unused counter %d should be accepted", seq)
		}
	}
	if w.accept(4) {
		t.Fatal("counter 4 has now been used and must be refused")
	}
}

func TestReplayWindowRejectsAncientAndZero(t *testing.T) {
	var w replayWindow
	if w.accept(0) {
		t.Fatal("counter 0 means the client never set one; it must be refused")
	}
	if !w.accept(500) {
		t.Fatal("500 should be accepted")
	}
	if w.accept(1) {
		t.Fatal("counter 1 has fallen out of the window and must be refused")
	}
	if w.accept(500 - 64) {
		t.Fatal("a counter exactly one window behind must be refused")
	}
	if !w.accept(500 - 63) {
		t.Fatal("a counter just inside the window should be accepted")
	}
}

func TestAuthThrottleBlocksAfterRepeatedFailures(t *testing.T) {
	th := newAuthThrottle()
	const ip = "192.168.1.50"

	for i := 0; i < guestAuthFails-1; i++ {
		if wait := th.bad(ip); wait != 0 {
			t.Fatalf("failure %d should not have triggered a timeout yet", i+1)
		}
		if blocked, _ := th.blocked(ip); blocked {
			t.Fatalf("address should not be blocked after %d failures", i+1)
		}
	}

	if wait := th.bad(ip); wait <= 0 {
		t.Fatal("crossing the failure threshold should impose a timeout")
	}
	blocked, wait := th.blocked(ip)
	if !blocked || wait <= 0 {
		t.Fatal("address should be serving a timeout now")
	}
}

func TestAuthThrottleForgivesOnSuccess(t *testing.T) {
	th := newAuthThrottle()
	const ip = "192.168.1.51"
	for i := 0; i < guestAuthFails; i++ {
		th.bad(ip)
	}
	if blocked, _ := th.blocked(ip); !blocked {
		t.Fatal("precondition: address should be blocked")
	}
	th.good(ip)
	if blocked, _ := th.blocked(ip); blocked {
		t.Fatal("a successful handshake should clear the timeout")
	}
}

func TestAuthThrottleIsPerAddress(t *testing.T) {
	th := newAuthThrottle()
	for i := 0; i < guestAuthFails+2; i++ {
		th.bad("192.168.1.52")
	}
	if blocked, _ := th.blocked("192.168.1.53"); blocked {
		t.Fatal("one address failing must not block a different one")
	}
}

func TestAllowedGuestSourceRejectsPublicAddresses(t *testing.T) {
	allowed := []string{"127.0.0.1", "10.0.0.51", "192.168.1.20", "172.16.4.4", "169.254.1.1", "100.72.1.1"}
	for _, ip := range allowed {
		if !allowedGuestSource(ip) {
			t.Fatalf("%s is a local-network address and should be allowed", ip)
		}
	}
	denied := []string{"8.8.8.8", "1.1.1.1", "203.0.113.7", "172.32.0.1", "not-an-ip", ""}
	for _, ip := range denied {
		if allowedGuestSource(ip) {
			t.Fatalf("%s is not a local-network address and should be refused", ip)
		}
	}
}

// The token is the HKDF salt, so two invites can never agree on the same key
// even if every other input matches.
func TestGuestKeysAreBoundToTheInviteToken(t *testing.T) {
	shared := []byte("0123456789abcdef0123456789abcdef")

	h2gA, g2hA, err := guestKeys(shared, "token-a", "invite", "sid")
	if err != nil {
		t.Fatalf("deriving keys failed: %v", err)
	}
	h2gB, _, err := guestKeys(shared, "token-b", "invite", "sid")
	if err != nil {
		t.Fatalf("deriving keys failed: %v", err)
	}

	nonce := make([]byte, 12)
	sealed := h2gA.Seal(nil, nonce, []byte("hello"), nil)

	if _, err := h2gB.Open(nil, nonce, sealed, nil); err == nil {
		t.Fatal("a different invite token must not decrypt this frame")
	}
	if _, err := g2hA.Open(nil, nonce, sealed, nil); err == nil {
		t.Fatal("the opposite direction must use a different key")
	}
}

func TestGuestKeysAreDeterministic(t *testing.T) {
	shared := []byte("0123456789abcdef0123456789abcdef")
	first, _, err := guestKeys(shared, "tok", "invite", "sid")
	if err != nil {
		t.Fatalf("deriving keys failed: %v", err)
	}
	_, second, err := guestKeys(shared, "tok", "invite", "sid")
	if err != nil {
		t.Fatalf("deriving keys failed: %v", err)
	}

	nonce := make([]byte, 12)
	sealed := first.Seal(nil, nonce, []byte("hello"), nil)
	// second is the g2h key from an identical derivation, so it must NOT open a
	// h2g frame; what we are checking is that derivation is stable, which the
	// round trip below proves.
	if _, err := second.Open(nil, nonce, sealed, nil); err == nil {
		t.Fatal("directional keys must differ")
	}

	again, _, err := guestKeys(shared, "tok", "invite", "sid")
	if err != nil {
		t.Fatalf("deriving keys failed: %v", err)
	}
	pt, err := again.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("the same inputs must derive the same key: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("round trip returned %q", pt)
	}
}

func TestInviteExpiry(t *testing.T) {
	past := nowMS() - time.Hour.Milliseconds()
	future := nowMS() + time.Hour.Milliseconds()

	if got := (&Invite{Expires: 0}).expired(); got {
		t.Fatal("an invite with no expiry must never expire")
	}
	if got := (&Invite{Expires: future}).expired(); got {
		t.Fatal("an invite expiring in the future is not expired")
	}
	if got := (&Invite{Expires: past}).expired(); !got {
		t.Fatal("an invite whose expiry has passed must report expired")
	}

	if (&Invite{Expires: past}).usable() {
		t.Fatal("an expired invite is not usable")
	}
	if (&Invite{Revoked: true}).usable() {
		t.Fatal("a revoked invite is not usable")
	}
	if !(&Invite{Expires: future}).usable() {
		t.Fatal("a live invite should be usable")
	}
}

func TestSlugifyProducesSafeFolderNames(t *testing.T) {
	cases := map[string]string{
		"Sam's Laptop":   "sams-laptop",
		"  spaced  out ": "spaced-out",
		"../../etc":      "etc",
		"C:\\Windows":    "cwindows",
		"???":            "",
		"Ünïcödé":        "ncd",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Fatalf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
