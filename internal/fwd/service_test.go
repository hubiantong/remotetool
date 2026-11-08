package fwd

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/proto"
	"remotetool/internal/session"
)

// ------------------------------------------------------------- test helpers ---

func newTestService(t *testing.T) *Service {
	t.Helper()
	store, err := config.Open(t.TempDir())
	if err != nil {
		t.Fatalf("config.Open: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewService(log, store)
}

// startEchoTarget listens on 127.0.0.1 and echoes every accepted connection
// back; each accept is reported on the returned channel.
func startEchoTarget(t *testing.T) (port int, accepted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case ch <- conn:
			default:
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

// addTestGrant populates s.grants the same way the fwd.grant RPC handler does.
func addTestGrant(s *Service, id, peerID, targetHost string, targetPort int) {
	if err := s.addGrant(id, peerID, targetHost, targetPort, s.nextGen(peerID)); err != nil {
		panic(err)
	}
}

// assertStreamClosed verifies HandleStream closed the stream: writes to the
// peer end of the pipe must fail once the receiving end is closed.
func assertStreamClosed(t *testing.T, client net.Conn) {
	t.Helper()
	_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("stream should have been closed by HandleStream")
	}
}

// assertNoDial verifies nothing dialed the target within a short window.
func assertNoDial(t *testing.T, accepted <-chan net.Conn) {
	t.Helper()
	select {
	case c := <-accepted:
		t.Fatalf("unexpected dial to target (conn %v)", c)
	case <-time.After(100 * time.Millisecond):
	}
}

// ------------------------------------------------------------------- tests ---

func TestGrantDial(t *testing.T) {
	s := newTestService(t)
	port, accepted := startEchoTarget(t)
	addTestGrant(s, "f1", "devA", "127.0.0.1", port)

	client, srv := net.Pipe()
	defer client.Close()
	go s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFwd, &proto.DataHeader{RuleID: "f1"}, srv)

	// Both directions: bytes written at the stream reach the echo target and
	// come back.
	msg := []byte("ping-fwd")
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write to stream: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("target was not dialed")
	}
}

func TestNoGrantRejected(t *testing.T) {
	s := newTestService(t)
	_, accepted := startEchoTarget(t)

	client, srv := net.Pipe()
	defer client.Close()
	s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFwd, &proto.DataHeader{RuleID: "unknown"}, srv)

	assertStreamClosed(t, client)
	assertNoDial(t, accepted)
}

func TestForeignGrantRejected(t *testing.T) {
	s := newTestService(t)
	port, accepted := startEchoTarget(t)
	addTestGrant(s, "f2", "devB", "127.0.0.1", port)

	client, srv := net.Pipe()
	defer client.Close()
	s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFwd, &proto.DataHeader{RuleID: "f2"}, srv)

	assertStreamClosed(t, client)
	assertNoDial(t, accepted)
}

func TestLegacyDialRejected(t *testing.T) {
	s := newTestService(t)
	port, accepted := startEchoTarget(t)

	client, srv := net.Pipe()
	defer client.Close()
	hdr := &proto.DataHeader{Dial: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFwd, hdr, srv)

	assertStreamClosed(t, client)
	assertNoDial(t, accepted)
}

func TestLoopbackEnforced(t *testing.T) {
	s := newTestService(t)
	peer := &session.Peer{ID: "devA"}

	// Default config: non-loopback bind refused, loopback allowed.
	if err := s.listenRemote(peer, "r1", "0.0.0.0", 0); err == nil {
		t.Fatal("0.0.0.0 must be refused by default")
	}
	if err := s.listenRemote(peer, "r2", "127.0.0.1", 0); err != nil {
		t.Fatalf("loopback listen must succeed: %v", err)
	}
	s.stopListener("r2")

	if err := s.store.Update(func(c *config.Config) { c.AllowNonLoopbackFwd = true }); err != nil {
		t.Fatalf("enable AllowNonLoopbackFwd: %v", err)
	}
	if err := s.listenRemote(peer, "r3", "0.0.0.0", 0); err != nil {
		t.Fatalf("0.0.0.0 must succeed once allowed: %v", err)
	}
	s.mu.Lock()
	rl, ok := s.listeners["r3"]
	s.mu.Unlock()
	if !ok {
		t.Fatal("listener r3 not registered")
	}
	if rl.Rule.PeerID != "devA" {
		t.Fatalf("listener rule PeerID = %q, want devA", rl.Rule.PeerID)
	}
	if ta := rl.ln.Addr().(*net.TCPAddr); !ta.IP.IsUnspecified() {
		t.Fatalf("listener bound to %v, want 0.0.0.0", ta.IP)
	}
	s.stopListener("r3")
}
