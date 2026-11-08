package filex

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"remotetool/internal/proto"
	"remotetool/internal/session"
	"remotetool/internal/transport"
)

// ------------------------------------------------------------- test doubles ---

// stubStream is an in-memory transport.Stream: Write records bytes, Read
// serves the queued bytes then blocks until Close (io.EOF).
type stubStream struct {
	mu      sync.Mutex
	written []byte
	in      []byte
	closed  bool
	closeCh chan struct{}
}

var _ transport.Stream = (*stubStream)(nil)

func newStubStream(in []byte) *stubStream {
	return &stubStream{in: append([]byte(nil), in...), closeCh: make(chan struct{})}
}

func (s *stubStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.in) > 0 {
			n := copy(p, s.in)
			s.in = s.in[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		ch := s.closeCh
		s.mu.Unlock()
		<-ch
	}
}

func (s *stubStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written = append(s.written, p...)
	return len(p), nil
}

func (s *stubStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	return nil
}

func (s *stubStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ------------------------------------------------------------------ helpers ---

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ------------------------------------------------------------------- tests ---

func TestFinalizeIdempotent(t *testing.T) {
	s := NewService(testLogger())
	s.OnProgress(func(Progress) {})

	dir := t.TempDir()
	if _, err := s.prepareRecv("x1", filepath.Join(dir, "a.bin"), 0, false, "overwrite", "devA"); err != nil {
		t.Fatalf("prepareRecv: %v", err)
	}
	if err := s.finalize("x1", "cafe"); err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	// A repeated xfer.complete for a still-registered transfer must be a
	// no-op success, not a close of the already-closed ready channel.
	if err := s.finalize("x1", "cafe"); err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	err := s.finalize("gone", "cafe")
	if err == nil || !strings.Contains(err.Error(), "no such transfer") {
		t.Fatalf("finalize of unknown id: err=%v, want 'no such transfer'", err)
	}
	s.cancel("x1") // release the part file so TempDir cleanup works on Windows
}

func TestForeignStreamRejected(t *testing.T) {
	s := NewService(testLogger())
	s.OnProgress(func(Progress) {})

	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	res, err := s.prepareRecv("x2", path, 0, false, "overwrite", "devA")
	if err != nil {
		t.Fatalf("prepareRecv: %v", err)
	}

	// A paired device that is not the transfer owner must be dropped before
	// any byte reaches the part file. The stub is closed up front so a
	// broken ownership check still returns instead of hanging the test.
	foreign := newStubStream([]byte("evil"))
	foreign.Close()
	s.HandleStream(&session.Peer{ID: "devB"}, proto.ChanFile, &proto.DataHeader{XferID: "x2"}, foreign)
	if !foreign.isClosed() {
		t.Fatal("foreign stream was not closed")
	}

	// The owning peer can still stream bytes; with sizeKnown=false the EOF
	// path reports "interrupted" and keeps the transfer registered.
	own := newStubStream([]byte("hello"))
	own.Close()
	s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFile, &proto.DataHeader{XferID: "x2"}, own)

	got, err := os.ReadFile(res.Path + partSuffix)
	if err != nil {
		t.Fatalf("read part file: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("part file contains %q, want only the owner's %q", got, "hello")
	}
	s.mu.Lock()
	rs := s.recv["x2"]
	s.mu.Unlock()
	if rs == nil {
		t.Fatal("receive state vanished")
	}
	rs.muSt.Lock()
	offset := rs.offset
	rs.muSt.Unlock()
	if offset != int64(len("hello")) {
		t.Fatalf("rs.offset = %d, want %d", offset, len("hello"))
	}
	s.cancel("x2") // release the part file so TempDir cleanup works on Windows
}

func TestUnknownXferIDRejected(t *testing.T) {
	s := NewService(testLogger())
	s.OnProgress(func(Progress) {})

	st := newStubStream([]byte("data"))
	st.Close()
	s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFile, &proto.DataHeader{XferID: "nosuch"}, st)
	if !st.isClosed() {
		t.Fatal("stream for unknown transfer was not closed")
	}
}
