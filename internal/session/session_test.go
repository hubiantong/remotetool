package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/identity"
	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

func newTestManager(t *testing.T) (*Manager, *identity.Identity) {
	t.Helper()
	id, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	store, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewManager(id, store, log), id
}

func setHelloTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := helloTimeout
	helloTimeout = d
	t.Cleanup(func() { helloTimeout = old })
}

type peerResult struct {
	p   *Peer
	err error
}

// acceptAsync accepts one inbound connection on ln and runs
// mgr.acceptHandshake on it, reporting the result.
func acceptAsync(t *testing.T, ln transport.Listener, mgr *Manager) <-chan peerResult {
	t.Helper()
	out := make(chan peerResult, 1)
	inbound := make(chan transport.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- peerResult{err: fmt.Errorf("listener accept: %w", err)}
			return
		}
		inbound <- conn
	}()
	go func() {
		var conn transport.Conn
		select {
		case conn = <-inbound:
		case <-time.After(5 * time.Second):
			out <- peerResult{err: errors.New("timed out waiting for inbound connection")}
			return
		}
		p, err := mgr.acceptHandshake(conn, conn.RemoteAddr().String())
		out <- peerResult{p: p, err: err}
	}()
	return out
}

func testListener(t *testing.T, id *identity.Identity) transport.Listener {
	t.Helper()
	// Loopback test: no pin verifier on either side.
	ln, err := transport.Listen("127.0.0.1:0", id.TLSConfig(nil))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestHandshakePair runs a full dialHandshake/acceptHandshake exchange and
// checks both sides end up with a Peer describing the other device.
func TestHandshakePair(t *testing.T) {
	setHelloTimeout(t, 300*time.Millisecond)

	acceptMgr, acceptID := newTestManager(t)
	dialMgr, dialID := newTestManager(t)
	ln := testListener(t, acceptID)

	acceptRes := acceptAsync(t, ln, acceptMgr)

	conn, err := transport.Dial(context.Background(), ln.Addr().String(), dialID.TLSConfig(nil))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	p, err := dialMgr.dialHandshake(context.Background(), conn, conn.RemoteAddr().String())
	if err != nil {
		t.Fatalf("dialHandshake: %v", err)
	}
	if p.ID != acceptID.ID {
		t.Errorf("dial side peer id = %q, want %q", p.ID, acceptID.ID)
	}
	if p.Name == "" {
		t.Error("dial side peer name is empty")
	}

	select {
	case r := <-acceptRes:
		if r.err != nil {
			t.Fatalf("acceptHandshake: %v", r.err)
		}
		if r.p.ID != dialID.ID {
			t.Errorf("accept side peer id = %q, want %q", r.p.ID, dialID.ID)
		}
		if r.p.Name == "" {
			t.Error("accept side peer name is empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for acceptHandshake")
	}
}

// TestAcceptHandshakeHelloTimeout: the dialer opens the control stream but
// never sends a hello, so acceptHandshake must fail with "hello timeout"
// shortly after helloTimeout instead of hanging.
func TestAcceptHandshakeHelloTimeout(t *testing.T) {
	const timeout = 300 * time.Millisecond
	setHelloTimeout(t, timeout)

	acceptMgr, acceptID := newTestManager(t)
	_, dialID := newTestManager(t)
	ln := testListener(t, acceptID)

	acceptRes := acceptAsync(t, ln, acceptMgr)

	conn, err := transport.Dial(context.Background(), ln.Addr().String(), dialID.TLSConfig(nil))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Open the control stream so acceptHandshake gets past conn.Accept(),
	// then stay silent. QUIC only delivers a stream to Accept once it carries
	// data, so write one no-op notify frame — anything but a hello.
	ctl, err := conn.Open()
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	if err := proto.WriteMessage(ctl, &proto.Message{Method: "ping"}); err != nil {
		t.Fatalf("write notify: %v", err)
	}

	select {
	case r := <-acceptRes:
		if r.err == nil {
			t.Fatal("acceptHandshake succeeded, want hello timeout error")
		}
		if !strings.Contains(r.err.Error(), "hello timeout") {
			t.Fatalf("acceptHandshake error = %v, want it to contain \"hello timeout\"", r.err)
		}
	case <-time.After(timeout + 3*time.Second):
		t.Fatal("acceptHandshake did not return within helloTimeout+slack")
	}
}
