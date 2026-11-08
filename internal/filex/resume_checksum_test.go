package filex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/session"
)

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

func payloadBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// drainProgress returns true once an event matching pred has been observed
// (draining the queue across polls).
func drainProgress(prog chan Progress, pred func(Progress) bool) bool {
	for {
		select {
		case p := <-prog:
			if pred(p) {
				return true
			}
		default:
			return false
		}
	}
}

// TestResumeChecksumMismatchCleanupAndRetry covers the resumable-transfer
// contract end to end: prepareRecv resumes from an existing .rtpart prefix,
// a checksum mismatch removes the part file and drops the receive state with
// an "error" progress event, and a fresh attempt then succeeds.
func TestResumeChecksumMismatchCleanupAndRetry(t *testing.T) {
	s := NewService(testLogger())
	prog := make(chan Progress, 64)
	s.OnProgress(func(p Progress) { prog <- p })

	payload := payloadBytes(8 << 10)
	prefix := payload[:3<<10]
	final := filepath.Join(t.TempDir(), "a.bin")
	part := final + partSuffix
	if err := os.WriteFile(part, prefix, 0o644); err != nil {
		t.Fatalf("write part file: %v", err)
	}

	// prepareRecv must hash the existing prefix and resume from it.
	res, err := s.prepareRecv("x1", final, int64(len(payload)), true, "overwrite", "devA")
	if err != nil {
		t.Fatalf("prepareRecv: %v", err)
	}
	if res.Offset != int64(len(prefix)) {
		t.Fatalf("resume offset = %d, want %d", res.Offset, len(prefix))
	}
	if res.Path != final {
		t.Fatalf("final path = %q, want %q", res.Path, final)
	}

	// Stream the remainder, then deliver a WRONG checksum (xfer.complete).
	st := newStubStream(payload[len(prefix):])
	st.Close()
	go s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFile,
		&proto.DataHeader{XferID: "x1"}, st)

	wrong := sha256.Sum256([]byte("not the payload"))
	if err := s.finalize("x1", hex.EncodeToString(wrong[:])); err != nil {
		t.Fatalf("xfer.complete with wrong checksum: %v", err)
	}

	// Mismatch cleanup: part file removed, receive state dropped, final file
	// never created, progress reports the error.
	waitFor(t, "mismatch cleanup (part removed, state dropped)", func() bool {
		_, statErr := os.Stat(part)
		s.mu.Lock()
		gone := s.recv["x1"] == nil
		s.mu.Unlock()
		return os.IsNotExist(statErr) && gone
	})
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("final file exists after checksum mismatch (stat err=%v)", err)
	}
	waitFor(t, "error progress event", func() bool {
		return drainProgress(prog, func(p Progress) bool {
			return p.ID == "x1" && p.State == "error" && strings.Contains(p.Err, "sha256 mismatch")
		})
	})

	// Retry with the correct checksum: the part file is gone, so the transfer
	// starts from zero and completes.
	res2, err := s.prepareRecv("x2", final, int64(len(payload)), true, "overwrite", "devA")
	if err != nil {
		t.Fatalf("retry prepareRecv: %v", err)
	}
	if res2.Offset != 0 {
		t.Fatalf("retry resume offset = %d, want 0 (mismatch must have removed the part file)", res2.Offset)
	}
	st2 := newStubStream(payload)
	st2.Close()
	go s.HandleStream(&session.Peer{ID: "devA"}, proto.ChanFile,
		&proto.DataHeader{XferID: "x2"}, st2)
	want := sha256.Sum256(payload)
	if err := s.finalize("x2", hex.EncodeToString(want[:])); err != nil {
		t.Fatalf("retry xfer.complete: %v", err)
	}

	waitFor(t, "retry receive state to drop", func() bool {
		s.mu.Lock()
		gone := s.recv["x2"] == nil
		s.mu.Unlock()
		return gone
	})
	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("final file holds %d bytes, want the full %d-byte payload", len(got), len(payload))
	}
	waitFor(t, "done progress event", func() bool {
		return drainProgress(prog, func(p Progress) bool {
			return p.ID == "x2" && p.State == "done"
		})
	})
}
