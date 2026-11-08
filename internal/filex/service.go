// Package filex implements chunked, resumable, checksum-verified file
// transfer plus the filesystem operations behind the remote file browser.
//
// Protocol shape (mirrors UU远程's Ask→Confirm→Block→Complete state machine,
// simplified for QUIC): the sender asks (xfer.push/xfer.pull), the receiver
// answers with the resume offset, file bytes stream raw on one data stream,
// and xfer.complete verifies SHA-256. An interrupted transfer leaves the
// .rtpart file so the next attempt resumes from the received offset.
package filex

import (
	"context"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"remotetool/internal/proto"
	"remotetool/internal/session"
	"remotetool/internal/transport"
)

const partSuffix = ".rtpart"
const pumpBuf = 256 << 10

// Progress reports transfer state to the UI.
type Progress struct {
	ID        string `json:"id"`
	PeerID    string `json:"peer_id"`
	Direction string `json:"direction"` // "push" (to peer) / "pull" (from peer)
	LocalPath string `json:"local_path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Done      int64  `json:"done"`
	State     string `json:"state"` // running|done|error|interrupted
	Err       string `json:"err,omitempty"`
}

// Service is the file transfer feature.
type Service struct {
	log *slog.Logger

	mu     sync.Mutex
	recv   map[string]*recvState // xferID -> inbound transfer
	onProg func(Progress)
}

// NewService builds the filex feature.
func NewService(log *slog.Logger) *Service {
	return &Service{log: log, recv: map[string]*recvState{}}
}

// OnProgress installs the progress sink.
func (s *Service) OnProgress(fn func(Progress)) { s.onProg = fn }

func (s *Service) progress(p Progress) {
	if s.onProg != nil {
		s.onProg(p)
	}
}

func (s *Service) Name() string   { return "file" }
func (s *Service) Chan() proto.Chan { return proto.ChanFile }

// -------------------------------------------------------------- RPC types ---

type entry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Dir     bool      `json:"dir"`
	ModTime time.Time `json:"mod_time"`
}

type listParams struct {
	Path string `json:"path"`
}
type listResult struct {
	Path    string  `json:"path"`
	Entries []entry `json:"entries"`
}

type pathParams struct {
	Path string `json:"path"`
}
type renameParams struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type removeParams struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}
type statResult struct {
	Size    int64     `json:"size"`
	Dir     bool      `json:"dir"`
	ModTime time.Time `json:"mod_time"`
}

type pushParams struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Conflict string `json:"conflict,omitempty"`
}
type pushResult struct {
	Offset int64  `json:"offset"`
	Path   string `json:"path"`
}

type pullParams struct {
	ID      string `json:"id"`
	SrcPath string `json:"src"`
	Offset  int64  `json:"offset,omitempty"` // receiver's resume offset
}
type pullResult struct {
	Size int64 `json:"size"`
}

type completeParams struct {
	ID     string `json:"id"`
	Sha256 string `json:"sha256"`
}

type cancelParams struct {
	ID string `json:"id"`
}

// AttachRPC registers this feature's control methods on a peer connection.
func (s *Service) AttachRPC(peer *session.Peer, rc *proto.RPCConn) {
	rc.Handle("fs.list", func(params json.RawMessage) (any, error) {
		var p listParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return s.listDir(p.Path)
	})
	rc.Handle("fs.mkdir", func(params json.RawMessage) (any, error) {
		var p pathParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if p.Path == "" {
			return nil, errors.New("path required")
		}
		return nil, os.MkdirAll(p.Path, 0o755)
	})
	rc.Handle("fs.rename", func(params json.RawMessage) (any, error) {
		var p renameParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return nil, os.Rename(p.From, p.To)
	})
	rc.Handle("fs.remove", func(params json.RawMessage) (any, error) {
		var p removeParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return nil, removePath(p.Path, p.Recursive)
	})
	rc.Handle("fs.stat", func(params json.RawMessage) (any, error) {
		var p pathParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.Path)
		if err != nil {
			return nil, err
		}
		return statResult{Size: fi.Size(), Dir: fi.IsDir(), ModTime: fi.ModTime()}, nil
	})

	rc.Handle("xfer.push", func(params json.RawMessage) (any, error) {
		var p pushParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return s.prepareRecv(p.ID, p.Path, p.Size, true, p.Conflict)
	})
	rc.Handle("xfer.pull", func(params json.RawMessage) (any, error) {
		var p pullParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		fi, err := os.Stat(p.SrcPath)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			return nil, errors.New("xfer.pull requires a file")
		}
		if p.Offset < 0 || p.Offset > fi.Size() {
			p.Offset = 0
		}
		go s.sendStream(peer, p.ID, p.SrcPath, fi.Size(), p.Offset)
		return pullResult{Size: fi.Size()}, nil
	})
	rc.Handle("xfer.complete", func(params json.RawMessage) (any, error) {
		var p completeParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return nil, s.finalize(p.ID, p.Sha256)
	})
	rc.Handle("xfer.cancel", func(params json.RawMessage) (any, error) {
		var p cancelParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		s.cancel(p.ID)
		return nil, nil
	})
}

// ------------------------------------------------------------ server side ---

func (s *Service) listDir(path string) (*listResult, error) {
	if path == "" {
		if runtime.GOOS == "windows" {
			return &listResult{Path: "", Entries: drives()}, nil
		}
		path = "/"
	}
	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	res := &listResult{Path: path, Entries: make([]entry, 0, len(names))}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(path, n))
		if err != nil {
			continue
		}
		res.Entries = append(res.Entries, entry{
			Name:    n,
			Size:    fi.Size(),
			Dir:     fi.IsDir(),
			ModTime: fi.ModTime(),
		})
	}
	return res, nil
}

func drives() []entry {
	var out []entry
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		if _, err := os.Stat(root); err == nil {
			out = append(out, entry{Name: root, Dir: true})
		}
	}
	return out
}

func removePath(path string, recursive bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		if recursive {
			return os.RemoveAll(path)
		}
		return os.Remove(path)
	}
	return os.Remove(path)
}

// recvState tracks one inbound transfer on this device.
type recvState struct {
	id        string
	finalPath string
	partPath  string
	f         *os.File
	hash      hash.Hash
	expected  string // set by xfer.complete
	offset    int64
	size      int64 // may be 0 until known
	sizeKnown bool
	peerID    string
	finOnce   sync.Once
	finDone   chan struct{}
	finErr    error
	ready     chan struct{} // closed once expected is set
	muSt      sync.Mutex
}

// prepareRecv sets up (or resumes) an inbound transfer.
func (s *Service) prepareRecv(id, path string, size int64, sizeKnown bool, conflict string) (*pushResult, error) {
	if id == "" || path == "" {
		return nil, errors.New("id and path required")
	}
	if conflict == "" {
		conflict = "rename"
	}
	final := path
	if _, err := os.Stat(final); err == nil {
		switch conflict {
		case "overwrite":
		case "skip":
			return nil, fmt.Errorf("exists: %s", final)
		default:
			final = uniquePath(final)
		}
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return nil, err
	}
	part := final + partSuffix
	var offset int64
	h := sha256.New()
	if fi, err := os.Stat(part); err == nil {
		// A previous attempt left a part file: hash its prefix and resume.
		if sizeKnown && size > 0 && (fi.Size() > size) {
			_ = os.Remove(part)
		} else {
			if pf, err := os.Open(part); err == nil {
				n, cerr := io.Copy(h, pf)
				_ = pf.Close()
				if cerr != nil {
					_ = os.Remove(part)
					h = sha256.New()
				} else {
					offset = n
				}
			}
		}
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	st := &recvState{
		id: id, finalPath: final, partPath: part, f: f,
		hash: h, offset: offset, size: size, sizeKnown: sizeKnown,
		ready: make(chan struct{}), finDone: make(chan struct{}),
	}
	s.mu.Lock()
	if old := s.recv[id]; old != nil {
		_ = old.f.Close()
	}
	s.recv[id] = st
	s.mu.Unlock()
	s.progress(Progress{ID: id, Direction: "pull", LocalPath: final, Name: filepath.Base(final), Size: size, Done: offset, State: "running"})
	return &pushResult{Offset: offset, Path: final}, nil
}

// HandleStream receives file bytes for a registered transfer.
func (s *Service) HandleStream(peer *session.Peer, _ proto.Chan, h *proto.DataHeader, st transport.Stream) {
	s.mu.Lock()
	rs := s.recv[h.XferID]
	s.mu.Unlock()
	if rs == nil {
		s.log.Warn("file stream for unknown transfer", "id", h.XferID)
		_ = st.Close()
		return
	}
	rs.muSt.Lock()
	if rs.peerID == "" {
		rs.peerID = peer.ID
	}
	if !rs.sizeKnown && rs.size == 0 {
		// pull transfers learn the size via the xfer.pull response; nothing
		// to do here.
	}
	rs.muSt.Unlock()

	buf := make([]byte, pumpBuf)
	lastReport := time.Now()
	for {
		n, err := st.Read(buf)
		if n > 0 {
			rs.muSt.Lock()
			_, werr := rs.f.Write(buf[:n])
			rs.hash.Write(buf[:n])
			rs.offset += int64(n)
			done := rs.offset
			size := rs.size
			rs.muSt.Unlock()
			if werr != nil {
				_ = st.Close()
				s.failRecv(rs.id, werr.Error())
				return
			}
			if time.Since(lastReport) > 400*time.Millisecond {
				lastReport = time.Now()
				s.progress(Progress{ID: rs.id, PeerID: peer.ID, Direction: "pull", LocalPath: rs.finalPath, Name: filepath.Base(rs.finalPath), Size: size, Done: done, State: "running"})
			}
		}
		if err != nil {
			_ = st.Close()
			rs.muSt.Lock()
			complete := rs.sizeKnown && rs.offset >= rs.size
			rs.muSt.Unlock()
			if complete {
				if ferr := s.finalize(rs.id, ""); ferr != nil && !errors.Is(ferr, errAwaitHash) {
					s.failRecv(rs.id, ferr.Error())
				}
			} else {
				s.progress(Progress{ID: rs.id, PeerID: peer.ID, Direction: "pull", LocalPath: rs.finalPath, Name: filepath.Base(rs.finalPath), Size: rs.size, Done: rs.offset, State: "interrupted"})
			}
			return
		}
	}
}

var errAwaitHash = errors.New("waiting for checksum")

// finalize renames the part file into place once the checksum is known.
func (s *Service) finalize(id, expected string) error {
	s.mu.Lock()
	rs := s.recv[id]
	s.mu.Unlock()
	if rs == nil {
		return fmt.Errorf("no such transfer %s", id)
	}
	if expected != "" {
		rs.muSt.Lock()
		rs.expected = expected
		rs.muSt.Unlock()
		close(rs.ready)
		return nil
	}
	// EOF path: wait briefly for xfer.complete to deliver the checksum.
	select {
	case <-rs.ready:
	case <-time.After(15 * time.Second):
		return errAwaitHash
	}
	rs.muSt.Lock()
	want := rs.expected
	got := hex.EncodeToString(rs.hash.Sum(nil))
	rs.muSt.Unlock()
	if want != got {
		_ = rs.f.Close()
		_ = os.Remove(rs.partPath)
		s.dropRecv(id)
		s.finish(rs, fmt.Errorf("sha256 mismatch"))
		s.log.Warn("sha256 mismatch", "file", rs.finalPath, "want", want, "got", got)
		return fmt.Errorf("sha256 mismatch for %s", rs.finalPath)
	}
	_ = rs.f.Close()
	if err := os.Rename(rs.partPath, rs.finalPath); err != nil {
		s.dropRecv(id)
		s.finish(rs, err)
		return err
	}
	s.dropRecv(id)
	s.finish(rs, nil)
	return nil
}

func (s *Service) finish(rs *recvState, err error) {
	rs.finOnce.Do(func() {
		rs.finErr = err
		close(rs.finDone)
		if err == nil {
			s.progress(Progress{ID: rs.id, PeerID: rs.peerID, Direction: "pull", LocalPath: rs.finalPath, Name: filepath.Base(rs.finalPath), Size: rs.size, Done: rs.offset, State: "done"})
		} else {
			s.progress(Progress{ID: rs.id, PeerID: rs.peerID, Direction: "pull", LocalPath: rs.finalPath, Name: filepath.Base(rs.finalPath), Size: rs.size, Done: rs.offset, State: "error", Err: err.Error()})
		}
	})
}

func (s *Service) failRecv(id, msg string) {
	s.mu.Lock()
	rs := s.recv[id]
	delete(s.recv, id)
	s.mu.Unlock()
	if rs == nil {
		return
	}
	_ = rs.f.Close()
	s.finish(rs, errors.New(msg))
}

func (s *Service) cancel(id string) {
	s.mu.Lock()
	rs := s.recv[id]
	delete(s.recv, id)
	s.mu.Unlock()
	if rs != nil {
		_ = rs.f.Close()
		_ = os.Remove(rs.partPath)
		s.finish(rs, errors.New("canceled"))
	}
}

func (s *Service) dropRecv(id string) {
	s.mu.Lock()
	delete(s.recv, id)
	s.mu.Unlock()
}

func uniquePath(p string) string {
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// ------------------------------------------------------------- client side ---

func newID() string {
	b := make([]byte, 8)
	_, _ = crypto_rand.Read(b)
	return hex.EncodeToString(b)
}

type progressFunc func(Progress)

// PushFile sends one local file to a remote path.
func (s *Service) PushFile(ctx context.Context, peer *session.Peer, localPath, remotePath, conflict string, onProg progressFunc) error {
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return errors.New("use PushDir for directories")
	}
	return s.pushOne(ctx, peer, localPath, remotePath, fi.Size(), conflict, onProg)
}

// PushDir sends a directory tree to a remote directory.
func (s *Service) PushDir(ctx context.Context, peer *session.Peer, localDir, remoteDir, conflict string, onProg progressFunc) error {
	return filepath.WalkDir(localDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		target := joinRemote(remoteDir, rel)
		if d.IsDir() {
			return s.Mkdir(ctx, peer, target)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return s.pushOne(ctx, peer, path, target, fi.Size(), conflict, onProg)
	})
}

func (s *Service) pushOne(ctx context.Context, peer *session.Peer, localPath, remotePath string, size int64, conflict string, onProg progressFunc) error {
	id := newID()
	name := filepath.Base(localPath)
	var res pushResult
	if err := peer.RPC(ctx, "xfer.push", pushParams{ID: id, Path: remotePath, Size: size, Conflict: conflict}, &res); err != nil {
		return fmt.Errorf("peer rejected %s: %w", name, err)
	}
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	// Hash the resume prefix so the sender's checksum covers the whole file
	// (the receiver's hash includes the bytes it already had).
	hash := sha256.New()
	if res.Offset > 0 {
		if _, err := io.CopyN(hash, f, res.Offset); err != nil {
			return err
		}
	}
	st, err := peer.OpenData(proto.ChanFile, &proto.DataHeader{XferID: id})
	if err != nil {
		return err
	}
	defer st.Close()

	done := res.Offset
	buf := make([]byte, pumpBuf)
	lastReport := time.Now()
	report := func(state, errMsg string) {
		if onProg != nil {
			onProg(Progress{ID: id, PeerID: peer.ID, Direction: "push", LocalPath: localPath, Name: name, Size: size, Done: done, State: state, Err: errMsg})
		}
	}
	report("running", "")
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, werr := st.Write(buf[:n]); werr != nil {
				report("error", werr.Error())
				_ = peer.RPC(context.Background(), "xfer.cancel", cancelParams{ID: id}, nil)
				return fmt.Errorf("send %s: %w", name, werr)
			}
			hash.Write(buf[:n])
			done += int64(n)
			if time.Since(lastReport) > 400*time.Millisecond {
				lastReport = time.Now()
				report("running", "")
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			report("error", rerr.Error())
			return rerr
		}
	}
	if err := peer.RPC(ctx, "xfer.complete", completeParams{ID: id, Sha256: hex.EncodeToString(hash.Sum(nil))}, nil); err != nil {
		report("error", err.Error())
		return err
	}
	report("done", "")
	return nil
}

// PullFile fetches a remote file into a local path.
func (s *Service) PullFile(ctx context.Context, peer *session.Peer, remotePath, localPath, conflict string, onProg progressFunc) error {
	if conflict == "" {
		conflict = "rename"
	}
	if localPath == "" {
		localPath = filepath.Join(".", filepath.Base(remotePath))
	}
	if fi, err := os.Stat(localPath); err == nil && !fi.IsDir() {
		switch conflict {
		case "overwrite":
		case "skip":
			return fmt.Errorf("exists: %s", localPath)
		default:
			localPath = uniquePath(localPath)
		}
	}
	id := newID()
	res, err := s.prepareRecv(id, localPath, 0, false, "overwrite")
	if err != nil {
		return err
	}
	localPath = res.Path
	s.mu.Lock()
	rs := s.recv[id]
	s.mu.Unlock()
	if rs == nil {
		return errors.New("receive state vanished")
	}
	rs.muSt.Lock()
	offset := rs.offset
	rs.muSt.Unlock()
	var pr pullResult
	if err := peer.RPC(ctx, "xfer.pull", pullParams{ID: id, SrcPath: remotePath, Offset: offset}, &pr); err != nil {
		s.cancel(id)
		return err
	}
	rs.muSt.Lock()
	rs.size = pr.Size
	rs.sizeKnown = true
	rs.muSt.Unlock()
	select {
	case <-rs.finDone:
		return rs.finErr
	case <-ctx.Done():
		s.cancel(id)
		return ctx.Err()
	}
}

// sendStream is the xfer.pull handler on the sending side: open a data
// stream to the requester and stream the file (resuming at offset), then
// report the whole-file checksum.
func (s *Service) sendStream(peer *session.Peer, id, srcPath string, size, offset int64) {
	f, err := os.Open(srcPath)
	if err != nil {
		s.log.Warn("xfer.pull open failed", "path", srcPath, "err", err)
		return
	}
	defer f.Close()
	hash := sha256.New()
	if offset > 0 {
		// The receiver already has [0, offset): hash it for the checksum and
		// skip sending it.
		if _, err := io.CopyN(hash, f, offset); err != nil {
			s.log.Warn("xfer.pull prefix read failed", "err", err)
			return
		}
	}
	st, err := peer.OpenData(proto.ChanFile, &proto.DataHeader{XferID: id})
	if err != nil {
		s.log.Warn("xfer.pull open stream failed", "err", err)
		return
	}
	defer st.Close()
	buf := make([]byte, pumpBuf)
	var done = offset
	lastReport := time.Now()
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, werr := st.Write(buf[:n]); werr != nil {
				s.log.Warn("xfer.pull send failed", "err", werr)
				return
			}
			hash.Write(buf[:n])
			done += int64(n)
			if time.Since(lastReport) > 400*time.Millisecond {
				lastReport = time.Now()
				s.progress(Progress{ID: id, PeerID: peer.ID, Direction: "push", LocalPath: srcPath, Name: filepath.Base(srcPath), Size: size, Done: done, State: "running"})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			s.progress(Progress{ID: id, PeerID: peer.ID, Direction: "push", LocalPath: srcPath, Name: filepath.Base(srcPath), Size: size, Done: done, State: "error", Err: rerr.Error()})
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := peer.RPC(ctx, "xfer.complete", completeParams{ID: id, Sha256: hex.EncodeToString(hash.Sum(nil))}, nil); err != nil {
		s.log.Warn("xfer.pull complete failed", "err", err)
		return
	}
	s.progress(Progress{ID: id, PeerID: peer.ID, Direction: "push", LocalPath: srcPath, Name: filepath.Base(srcPath), Size: size, Done: done, State: "done"})
}

// --------------------------------------------------------------- fs proxy ---

// ListDir lists a directory on a peer.
func (s *Service) ListDir(ctx context.Context, peer *session.Peer, path string) (*listResult, error) {
	var res listResult
	err := peer.RPC(ctx, "fs.list", listParams{Path: path}, &res)
	return &res, err
}

// Mkdir creates a directory on a peer.
func (s *Service) Mkdir(ctx context.Context, peer *session.Peer, path string) error {
	return peer.RPC(ctx, "fs.mkdir", pathParams{Path: path}, nil)
}

// Rename renames a path on a peer.
func (s *Service) Rename(ctx context.Context, peer *session.Peer, from, to string) error {
	return peer.RPC(ctx, "fs.rename", renameParams{From: from, To: to}, nil)
}

// Remove deletes a path on a peer.
func (s *Service) Remove(ctx context.Context, peer *session.Peer, path string, recursive bool) error {
	return peer.RPC(ctx, "fs.remove", removeParams{Path: path, Recursive: recursive}, nil)
}

// Stat stats a path on a peer.
func (s *Service) Stat(ctx context.Context, peer *session.Peer, path string) (*statResult, error) {
	var res statResult
	err := peer.RPC(ctx, "fs.stat", pathParams{Path: path}, &res)
	return &res, err
}

func joinRemote(base, rel string) string {
	if rel == "." {
		return base
	}
	clean := filepath.ToSlash(rel)
	return strings.TrimRight(base, "/\\") + string(filepath.Separator) + filepath.FromSlash(clean)
}
