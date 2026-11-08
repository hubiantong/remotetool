// PairService implements the 6-digit pairing-code handshake (SPAKE2 with TLS
// channel binding, see internal/identity/spake2.go) on both roles:
// verifier (generates the code) and prover (enters the code on the other
// device). It replaces UU远程's assist code with a decentralized mechanism:
// no account, no third-party server.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"remotetool/internal/config"
	"remotetool/internal/identity"
	"remotetool/internal/proto"
	"remotetool/internal/transport"
)

const inviteTTL = 5 * time.Minute

// Brute-force protection knobs (fix F2).
var backoffBase = 2 * time.Second // package var so tests can shrink it

const (
	maxBackoff        = 5 * time.Minute // per-caller backoff cap
	maxInviteAttempts = 5               // wrong codes before the invite is invalidated
	maxFailStates     = 1024            // per-caller backoff table cap
	unpairedConns     = 8               // concurrent unpaired connections handled
	unpairedRefill    = 10              // unpaired connections admitted per second
	unpairedBurst     = 20              // unpaired connection burst
)

// errPairingFailed is the one error peers ever see from a pairing failure
// (no invite, expired, wrong code, backoff, overload). The specific reason is
// logged server-side only, so failures cannot be probed.
var errPairingFailed = errors.New("pairing failed")

type invite struct {
	Code     string    `json:"code"`
	Expires  time.Time `json:"expires"`
	Attempts int       `json:"attempts"` // wrong codes received
}

// failState tracks consecutive wrong codes from one caller and when it may
// try again (exponential backoff).
type failState struct {
	fails       int
	nextAllowed time.Time
}

// tokenBucket refills at a constant rate up to a burst size.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newTokenBucket() *tokenBucket {
	return &tokenBucket{tokens: unpairedBurst, last: time.Now()}
}

// allow consumes one token at time now, first refilling for the elapsed time.
func (tb *tokenBucket) allow(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.last.IsZero() {
		tb.tokens += now.Sub(tb.last).Seconds() * unpairedRefill
	}
	if tb.tokens > unpairedBurst {
		tb.tokens = unpairedBurst
	}
	tb.last = now
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// backoffFor is the wait after n consecutive wrong codes:
// backoffBase << (n-1), capped at maxBackoff.
func backoffFor(n int) time.Duration {
	d := backoffBase
	for i := 1; i < n; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// PairService owns pairing state.
type PairService struct {
	id    *identity.Identity
	store *config.Store
	log   *slog.Logger

	mu     sync.Mutex
	invite *invite
	// fails holds wrong-code backoff state keyed by remote device id (or
	// network address when the id is unknown).
	fails map[string]*failState

	sem  chan struct{} // bounds concurrent HandleUnpairedConn goroutines
	rate *tokenBucket  // bounds the unpaired connection admission rate
}

func NewPairService(id *identity.Identity, store *config.Store, log *slog.Logger) *PairService {
	return &PairService{
		id:    id,
		store: store,
		log:   log,
		fails: map[string]*failState{},
		sem:   make(chan struct{}, unpairedConns),
		rate:  newTokenBucket(),
	}
}

// CreateInvite generates a fresh code, replacing any previous one.
func (ps *PairService) CreateInvite() (string, time.Time, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.invite = &invite{Code: identity.NewPairingCode(), Expires: time.Now().Add(inviteTTL)}
	return ps.invite.Code, ps.invite.Expires, nil
}

// CurrentInvite returns the pending invite, if any.
func (ps *PairService) CurrentInvite() (string, time.Time, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.invite == nil || time.Now().After(ps.invite.Expires) {
		return "", time.Time{}, false
	}
	return ps.invite.Code, ps.invite.Expires, true
}

// failKey identifies the remote side for backoff bookkeeping: the pinned
// device id when known, otherwise the network address.
func failKey(conn transport.Conn) string {
	if id := conn.RemoteID(); id != "" {
		return id
	}
	return conn.RemoteAddr().String()
}

// checkRequest decides a pair.request: per-caller backoff, invite presence
// and expiry, code comparison and wrong-code accounting, all under ps.mu in
// one critical section. It returns the live invite on success; every failure
// returns errPairingFailed, with the specific reason logged server-side only.
// now is a parameter so tests can drive the backoff clock.
func (ps *PairService) checkRequest(key, code string, now time.Time) (*invite, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Inside a backoff window: reject before looking at the invite, so wrong
	// codes cannot be tried faster than the backoff allows.
	if fs := ps.fails[key]; fs != nil && now.Before(fs.nextAllowed) {
		ps.log.Warn("pairing failed", "peer", key, "reason", "backoff")
		return nil, errPairingFailed
	}

	inv := ps.invite
	if inv == nil || now.After(inv.Expires) {
		ps.log.Warn("pairing failed", "peer", key, "reason", "no pending invite")
		return nil, errPairingFailed
	}

	if code != inv.Code {
		inv.Attempts++
		if err := ps.recordWrongCodeLocked(key, now); err != nil {
			ps.log.Warn("pairing failed", "peer", key, "reason", "backoff table full")
			return nil, errPairingFailed
		}
		if inv.Attempts >= maxInviteAttempts {
			ps.invite = nil // too many wrong codes: invalidate immediately
			ps.log.Warn("pairing failed", "peer", key, "reason", "wrong code, invite invalidated", "attempts", inv.Attempts)
		} else {
			ps.log.Warn("pairing failed", "peer", key, "reason", "wrong code", "attempts", inv.Attempts)
		}
		return nil, errPairingFailed
	}
	return inv, nil
}

// recordWrongCodeLocked bumps the failure count for key and schedules the
// next allowed attempt with exponential backoff. ps.mu must be held.
func (ps *PairService) recordWrongCodeLocked(key string, now time.Time) error {
	if fs, ok := ps.fails[key]; ok {
		fs.fails++
		fs.nextAllowed = now.Add(backoffFor(fs.fails))
		return nil
	}
	if len(ps.fails) >= maxFailStates {
		// Insert-time prune: drop entries whose backoff has been served.
		for k, fs := range ps.fails {
			if now.After(fs.nextAllowed) {
				delete(ps.fails, k)
			}
		}
		if len(ps.fails) >= maxFailStates {
			return errPairingFailed
		}
	}
	ps.fails[key] = &failState{fails: 1, nextAllowed: now.Add(backoffFor(1))}
	return nil
}

type pairRequestParams struct {
	Code  string   `json:"code"`
	Name  string   `json:"name"`
	Caps  []string `json:"caps,omitempty"`
	Share []byte   `json:"share"`
}
type pairRequestResult struct {
	Name    string   `json:"name"`
	Caps    []string `json:"caps,omitempty"`
	Share   []byte   `json:"share"`
	Confirm []byte   `json:"confirm"`
}
type pairConfirmParams struct {
	Confirm []byte `json:"confirm"`
}
type pairConfirmResult struct {
	Confirm []byte `json:"confirm"`
}

// HandleUnpairedConn runs the verifier side of pairing on an inbound
// connection from an unknown device.
func (ps *PairService) HandleUnpairedConn(conn transport.Conn) {
	// Resource limits first: unbounded concurrent unpaired connections or an
	// unbounded arrival rate would starve the daemon (fix F2).
	select {
	case ps.sem <- struct{}{}:
		defer func() { <-ps.sem }()
	default:
		ps.log.Warn("pairing connection rejected", "peer", failKey(conn), "reason", "concurrency limit")
		_ = conn.Close()
		return
	}
	if !ps.rate.allow(time.Now()) {
		ps.log.Warn("pairing connection rejected", "peer", failKey(conn), "reason", "rate limit")
		_ = conn.Close()
		return
	}
	defer conn.Close()
	ctl, err := conn.Accept()
	if err != nil {
		return
	}
	rc := proto.NewRPCConn(ctl)
	ps.attachTo(conn, rc)
	go rc.Serve()
	// The connection ends when the prover closes it.
	select {
	case <-rc.Done():
	case <-time.After(2 * time.Minute):
	}
}

// AttachPairHandlers exposes the pairing protocol on an already-established
// session, so re-pairing works even when both devices know each other.
func (ps *PairService) AttachPairHandlers(conn transport.Conn, rc *proto.RPCConn) {
	ps.attachTo(conn, rc)
}

// attachTo registers pair.request/pair.confirm handlers with per-connection
// SPAKE2 state.
func (ps *PairService) attachTo(conn transport.Conn, rc *proto.RPCConn) {
	var spk *identity.SPAKE2
	var pendingInv *invite // invite captured at pair.request time
	var peerName string
	rc.Handle("pair.request", func(params json.RawMessage) (any, error) {
		var p pairRequestParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, errPairingFailed
		}
		// Invite validity, wrong-code counting and backoff are decided in one
		// critical section; the SPAKE2 exchange runs outside the lock.
		inv, err := ps.checkRequest(failKey(conn), p.Code, time.Now())
		if err != nil {
			return nil, err
		}
		code := inv.Code // validated under the lock; immutable afterwards
		peerID := conn.RemoteID()
		s, err := identity.NewSPAKE2(identity.RoleVerifier, []byte(code),
			[]byte(peerID), []byte(ps.id.ID), conn.ChannelBinding())
		if err != nil {
			ps.log.Warn("pairing failed", "peer", failKey(conn), "reason", err)
			return nil, errPairingFailed
		}
		y, err := s.CreateShare()
		if err != nil {
			ps.log.Warn("pairing failed", "peer", failKey(conn), "reason", err)
			return nil, errPairingFailed
		}
		confirm, err := s.Finish(p.Share)
		if err != nil {
			ps.log.Warn("pairing failed", "peer", failKey(conn), "reason", err)
			return nil, errPairingFailed
		}
		spk, pendingInv, peerName = s, inv, p.Name
		return pairRequestResult{Name: ps.store.Get().Name, Share: y, Confirm: confirm}, nil
	})
	rc.Handle("pair.confirm", func(params json.RawMessage) (any, error) {
		if spk == nil {
			return nil, errPairingFailed
		}
		var p pairConfirmParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, errPairingFailed
		}
		// The invite may have been invalidated between pair.request and
		// pair.confirm (expired, or burned by another device's wrong codes).
		ps.mu.Lock()
		if ps.invite == nil || ps.invite != pendingInv {
			ps.mu.Unlock()
			ps.log.Warn("pairing failed", "peer", failKey(conn), "reason", "invite no longer pending")
			return nil, errPairingFailed
		}
		ps.mu.Unlock()
		if err := spk.VerifyConfirm(p.Confirm); err != nil {
			ps.log.Warn("pairing failed", "peer", failKey(conn), "reason", err)
			return nil, errPairingFailed
		}
		// Mutual confirmation succeeded: pin the peer.
		peerID := conn.RemoteID()
		err := ps.store.UpsertPeer(config.Peer{
			ID:       peerID,
			Name:     peerName,
			PubKey:   conn.RemotePub(),
			LastAddr: addrOf(conn),
		})
		if err != nil {
			return nil, err
		}
		ps.log.Info("paired with device", "id", peerID, "name", peerName)
		ps.mu.Lock()
		// Invalidate the invite (single use) and clear this caller's backoff.
		if ps.invite == pendingInv {
			ps.invite = nil
		}
		delete(ps.fails, failKey(conn))
		ps.mu.Unlock()
		return pairConfirmResult{Confirm: nil}, nil
	})
}

func addrOf(conn transport.Conn) string { return conn.RemoteAddr().String() }

// PairWith dials a remote device and runs the prover side of pairing.
func (ps *PairService) PairWith(ctx context.Context, addr, code string) (*config.Peer, error) {
	if code == "" {
		return nil, errors.New("pairing code required")
	}
	// Pairing mode accepts any self-signed Ed25519 certificate; the code +
	// channel binding authenticate the peer.
	conn, err := transport.Dial(ctx, addr, ps.id.TLSConfig(nil))
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()
	ctl, err := conn.Open()
	if err != nil {
		return nil, err
	}
	rc := proto.NewRPCConn(ctl)
	go rc.Serve()

	// Say hello first: if the peer considers us already paired, this
	// completes its normal session handshake and the pair handlers attach
	// to the same control stream. On the pure pairing path the peer has no
	// hello handler and the error is ignored.
	var theirHello struct {
		Name string `json:"name"`
	}
	_ = rc.Call(ctx, "hello", map[string]any{"id": ps.id.ID, "name": ps.store.Get().Name}, &theirHello)

	peerID := conn.RemoteID()
	spk, err := identity.NewSPAKE2(identity.RoleProver, []byte(code),
		[]byte(ps.id.ID), []byte(peerID), conn.ChannelBinding())
	if err != nil {
		return nil, err
	}
	x, err := spk.CreateShare()
	if err != nil {
		return nil, err
	}
	var res pairRequestResult
	if err := rc.Call(ctx, "pair.request", pairRequestParams{
		Code: code, Name: ps.store.Get().Name, Share: x,
	}, &res); err != nil {
		return nil, err
	}
	confirmA, err := spk.Finish(res.Share)
	if err != nil {
		return nil, err
	}
	if err := spk.VerifyConfirm(res.Confirm); err != nil {
		return nil, err
	}
	if err := rc.Call(ctx, "pair.confirm", pairConfirmParams{Confirm: confirmA}, nil); err != nil {
		return nil, err
	}
	pub := conn.RemotePub()
	if pub == nil {
		return nil, errors.New("peer identity unavailable")
	}
	peer := &config.Peer{ID: peerID, Name: res.Name, PubKey: pub, LastAddr: addr}
	if err := ps.store.UpsertPeer(*peer); err != nil {
		return nil, err
	}
	ps.log.Info("paired with device", "id", peerID, "name", res.Name)
	return peer, nil
}
