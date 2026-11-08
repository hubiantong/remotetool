package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/identity"
	"remotetool/internal/transport"
)

// countingListener wraps a listener and counts accepted connections, so a
// test can assert exactly one dial happened.
type countingListener struct {
	transport.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (transport.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// pairStores marks each manager's counterpart as a paired peer so Connect /
// ServeListener run the normal pin-verified path.
func pairStores(a, b *Manager, idA, idB *identity.Identity) {
	tA := a.store
	_ = tA.UpsertPeer(config.Peer{ID: idB.ID, Name: "b", PubKey: idB.Pub})
	tB := b.store
	_ = tB.UpsertPeer(config.Peer{ID: idA.ID, Name: "a", PubKey: idA.Pub})
}

// TestConnectSingleFlight: two concurrent Connect calls for the same peer
// must share ONE dial — exactly one inbound connection is accepted, and both
// callers get the very same *Peer object (leader result or Get hit).
func TestConnectSingleFlight(t *testing.T) {
	acceptMgr, acceptID := newTestManager(t)
	dialMgr, dialID := newTestManager(t)
	pairStores(acceptMgr, dialMgr, acceptID, dialID)

	ln := &countingListener{Listener: testListener(t, acceptID)}
	go acceptMgr.ServeListener(ln)
	dialMgr.AddCandidate(acceptID.ID, ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		p1, p2     *Peer
		err1, err2 error
		wg         sync.WaitGroup
	)
	wg.Add(2)
	go func() { defer wg.Done(); p1, err1 = dialMgr.Connect(ctx, acceptID.ID) }()
	go func() { defer wg.Done(); p2, err2 = dialMgr.Connect(ctx, acceptID.ID) }()
	wg.Wait()

	if err1 != nil || err2 != nil {
		t.Fatalf("Connect errors: %v / %v", err1, err2)
	}
	if p1 == nil || p2 == nil {
		t.Fatal("Connect returned nil peers")
	}
	if p1.ID != acceptID.ID || p2.ID != acceptID.ID {
		t.Fatalf("peer ids = %q / %q, want %q", p1.ID, p2.ID, acceptID.ID)
	}
	if p1 != p2 {
		t.Fatal("concurrent Connect calls returned different peer objects")
	}
	if n := ln.accepted.Load(); n != 1 {
		t.Fatalf("listener accepted %d connections, want exactly 1", n)
	}
	dialMgr.Disconnect(acceptID.ID)
}

// TestConnectWaitsOnInFlightDial simulates the single-flight leader by
// pre-registering a pending dialCall: concurrent Connect waiters must block
// until it finishes and then return the same peer — not dial themselves.
func TestConnectWaitsOnInFlightDial(t *testing.T) {
	m, _ := newTestManager(t)

	m.mu.Lock()
	dc := &dialCall{done: make(chan struct{})}
	m.dialing["devX"] = dc
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		delete(m.dialing, "devX")
		m.mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type result struct {
		p   *Peer
		err error
	}
	res := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			p, err := m.Connect(ctx, "devX")
			res <- result{p, err}
		}()
	}

	// While the dial is pending neither caller may return. A broken waiter
	// would dial "devX" itself and fail fast ("not paired with devX").
	select {
	case r := <-res:
		t.Fatalf("a Connect returned while the dial was still pending: peer=%v err=%v", r.p, r.err)
	case <-time.After(150 * time.Millisecond):
	}

	shared := &Peer{ID: "devX", Name: "shared"}
	dc.peer = shared
	close(dc.done)

	for i := 0; i < 2; i++ {
		select {
		case r := <-res:
			if r.err != nil {
				t.Fatalf("Connect error: %v", r.err)
			}
			if r.p != shared {
				t.Fatal("Connect did not return the shared dial result")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Connect did not return after the pending dial finished")
		}
	}
}

// TestConnectSharesDialError: waiters must also receive the leader's failure.
func TestConnectSharesDialError(t *testing.T) {
	m, _ := newTestManager(t)

	m.mu.Lock()
	dc := &dialCall{done: make(chan struct{})}
	m.dialing["devX"] = dc
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		delete(m.dialing, "devX")
		m.mu.Unlock()
	})

	dc.err = errors.New("dial failed")
	close(dc.done)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, err1 = m.Connect(ctx, "devX") }()
	go func() { defer wg.Done(); _, err2 = m.Connect(ctx, "devX") }()
	wg.Wait()

	if err1 == nil || err2 == nil {
		t.Fatalf("waiters must receive the dial error, got %v / %v", err1, err2)
	}
	if err1.Error() != "dial failed" || err2.Error() != "dial failed" {
		t.Fatalf("waiter errors differ from the dial error: %v / %v", err1, err2)
	}
}
