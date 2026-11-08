package term

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/session"
	"remotetool/internal/transport"
)

// ------------------------------------------------------------- test doubles ---

// fakePTY is an in-memory PTY: tests push output for the service's readLoop,
// stdin writes from attached clients are recorded for assertions.
type fakePTY struct {
	mu     sync.Mutex
	out    []byte
	sig    chan struct{} // closed+replaced when output or close arrives
	stdin  []byte
	closed bool
	done   chan struct{}
	once   sync.Once
}

var _ PTY = (*fakePTY)(nil)

func newFakePTY() *fakePTY {
	return &fakePTY{sig: make(chan struct{}), done: make(chan struct{})}
}

// push queues pty output, as if the shell had printed it.
func (f *fakePTY) push(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.out = append(f.out, data...)
	close(f.sig)
	f.sig = make(chan struct{})
}

func (f *fakePTY) stdinBytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.stdin...)
}

func (f *fakePTY) Read(p []byte) (int, error) {
	for {
		f.mu.Lock()
		if len(f.out) > 0 {
			n := copy(p, f.out)
			f.out = f.out[n:]
			f.mu.Unlock()
			return n, nil
		}
		if f.closed {
			f.mu.Unlock()
			return 0, io.EOF
		}
		sig := f.sig
		f.mu.Unlock()
		<-sig
	}
}

func (f *fakePTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("pty closed")
	}
	f.stdin = append(f.stdin, p...)
	return len(p), nil
}

func (f *fakePTY) Close() error { return f.stop() }

func (f *fakePTY) Kill() error { return f.stop() }

func (f *fakePTY) stop() error {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.sig)
		f.sig = make(chan struct{})
	}
	f.mu.Unlock()
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakePTY) Resize(cols, rows uint16) error { return nil }

func (f *fakePTY) Wait() (int, error) {
	<-f.done
	return 0, nil
}

// fakeStream is an in-memory transport.Stream: output written by the service
// is recorded; Read serves queued stdin then blocks until Close (io.EOF).
type fakeStream struct {
	mu      sync.Mutex
	written []byte
	in      []byte
	sig     chan struct{} // closed+replaced when stdin input arrives
	closed  bool
	closeCh chan struct{}
}

var _ transport.Stream = (*fakeStream)(nil)

func newFakeStream() *fakeStream {
	return &fakeStream{sig: make(chan struct{}), closeCh: make(chan struct{})}
}

// pushInput queues client -> pty bytes for the service's stdin loop.
func (f *fakeStream) pushInput(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.in = append(f.in, data...)
	close(f.sig)
	f.sig = make(chan struct{})
}

func (f *fakeStream) snapshot() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.written...)
}

func (f *fakeStream) Read(p []byte) (int, error) {
	for {
		f.mu.Lock()
		if len(f.in) > 0 {
			n := copy(p, f.in)
			f.in = f.in[n:]
			f.mu.Unlock()
			return n, nil
		}
		if f.closed {
			f.mu.Unlock()
			return 0, io.EOF
		}
		sig := f.sig
		f.mu.Unlock()
		select {
		case <-sig:
		case <-f.closeCh:
			return 0, io.EOF
		}
	}
}

func (f *fakeStream) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, errors.New("stream closed")
	}
	f.written = append(f.written, p...)
	return len(p), nil
}

func (f *fakeStream) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	close(f.closeCh)
	return nil
}

// ------------------------------------------------------------------ helpers ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// swapPTY points the PTY constructor at an in-memory fake for one test.
func swapPTY(t *testing.T, fp *fakePTY) {
	t.Helper()
	old := startPTY
	startPTY = func(cols, rows uint16, shell, cwd string) (PTY, error) {
		return fp, nil
	}
	t.Cleanup(func() { startPTY = old })
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// wantQuiet waits until the stream carries at least want bytes, gives any
// straggler write a moment to land, and returns the received bytes.
func wantQuiet(t *testing.T, st *fakeStream, want []byte) []byte {
	t.Helper()
	waitFor(t, "stream to receive the full output", func() bool {
		return len(st.snapshot()) >= len(want)
	})
	time.Sleep(50 * time.Millisecond) // a duplicate write would land by now
	got := st.snapshot()
	if len(got) != len(want) {
		t.Fatalf("stream carries %d bytes, want exactly %d", len(got), len(want))
	}
	return got
}

// ------------------------------------------------------------------- tests ---

func TestSessionOwnership(t *testing.T) {
	s := NewService(testLogger())
	fp := newFakePTY()
	swapPTY(t, fp)

	res, err := s.open("devA", openParams{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s.getOwned("devB", res.Session) != nil {
		t.Fatal("foreign device can reach the session via getOwned")
	}
	if s.getOwned("devA", res.Session) == nil {
		t.Fatal("owner cannot reach its own session")
	}
	if n := len(s.list("devB")); n != 0 {
		t.Fatalf("term.list showed the session to a foreign device (%d entries)", n)
	}
	if n := len(s.list("devA")); n != 1 {
		t.Fatalf("term.list for the owner has %d sessions, want 1", n)
	}

	// A foreign device attaching must be dropped exactly like an unknown
	// session: stream closed, nothing attached, nothing written.
	st := newFakeStream()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(&session.Peer{ID: "devB"}, proto.ChanTerm,
			&proto.DataHeader{Session: res.Session}, st)
	}()
	select {
	case <-st.closeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("foreign stream was not closed")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleStream did not return after closing the foreign stream")
	}
	if got := st.snapshot(); len(got) != 0 {
		t.Fatalf("foreign stream received %d bytes of output", len(got))
	}
	sess := s.getOwned("devA", res.Session)
	if sess == nil {
		t.Fatal("session vanished after a foreign attach attempt")
	}
	sess.mu.Lock()
	attached := sess.stream != nil
	sess.mu.Unlock()
	if attached {
		t.Fatal("foreign stream was attached to the session")
	}
}

func TestReplayOrderOnReconnect(t *testing.T) {
	s := NewService(testLogger())
	fp := newFakePTY()
	swapPTY(t, fp)

	res, err := s.open("devA", openParams{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	peer := &session.Peer{ID: "devA"}
	hdr := &proto.DataHeader{Session: res.Session}

	var full []byte // every byte pushed through the pty, in order
	push := func(n int) {
		for i := 0; i < n; i++ {
			chunk := []byte(fmt.Sprintf("chunk-%04d\n", len(full)/10))
			fp.push(chunk)
			full = append(full, chunk...)
		}
	}
	attach := func() *fakeStream {
		st := newFakeStream()
		go s.HandleStream(peer, proto.ChanTerm, hdr, st)
		return st
	}

	push(50) // output from before the first attach is replayed on attach

	st := attach()
	if got := wantQuiet(t, st, full); !bytes.Equal(got, full) {
		t.Fatalf("first attach: got %d bytes that differ from the full output", len(got))
	}

	// Stdin still flows client -> pty through the new attach path.
	st.pushInput([]byte("echo hi\n"))
	waitFor(t, "stdin to reach the pty", func() bool {
		return bytes.HasSuffix(fp.stdinBytes(), []byte("echo hi\n"))
	})

	// Detach / push / re-attach: every attach must see the full ring, in
	// order, exactly once.
	for i := 0; i < 30; i++ {
		_ = st.Close() // detach; the session keeps running
		push(3)
		st = attach()
		if got := wantQuiet(t, st, full); !bytes.Equal(got, full) {
			t.Fatalf("attach %d: got %d bytes, want %d in order", i, len(got), len(full))
		}
	}
	_ = st.Close()

	if s.getOwned("devA", res.Session) == nil {
		t.Fatal("session died across the attach/detach cycles")
	}
}

func TestScrollbackTrim(t *testing.T) {
	s := NewService(testLogger())
	fp := newFakePTY()
	swapPTY(t, fp)

	res, err := s.open("devA", openParams{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	peer := &session.Peer{ID: "devA"}
	hdr := &proto.DataHeader{Session: res.Session}

	var full []byte
	push := func(total, chunk int) {
		for done := 0; done < total; {
			n := min(chunk, total-done)
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte('a' + (len(full)+i)%26)
			}
			fp.push(buf)
			full = append(full, buf...)
			done += n
		}
	}

	sess := s.getOwned("devA", res.Session)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Push past the scrollback limit in several shapes, then attach: the
	// replay must be exactly the last scrollback bytes, whatever was trimmed.
	// The pty drain is asynchronous, so first wait for the ring to settle.
	for _, round := range []struct{ total, chunk int }{
		{scrollback + 800, 1000},
		{scrollback + 50<<10, 4 << 10},
		{2 * scrollback, 32 << 10},
	} {
		push(round.total, round.chunk)
		waitFor(t, "scrollback to settle", func() bool {
			sess.mu.Lock()
			defer sess.mu.Unlock()
			return len(sess.ring) == scrollback && sess.ringBase == len(full)-scrollback
		})
		want := full[len(full)-scrollback:]
		st := newFakeStream()
		go s.HandleStream(peer, proto.ChanTerm, hdr, st)
		if got := wantQuiet(t, st, want); !bytes.Equal(got, want) {
			t.Fatalf("replay after trim: got %d bytes, want the last %d in order", len(got), len(want))
		}
		_ = st.Close()
	}

	if s.getOwned("devA", res.Session) == nil {
		t.Fatal("session died across the scrollback rounds")
	}
}
