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

type invite struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

// PairService owns pairing state.
type PairService struct {
	id    *identity.Identity
	store *config.Store
	log   *slog.Logger

	mu      sync.Mutex
	invite  *invite
	pairing bool
}

func NewPairService(id *identity.Identity, store *config.Store, log *slog.Logger) *PairService {
	return &PairService{id: id, store: store, log: log}
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

type pairRequestParams struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Caps  []string `json:"caps,omitempty"`
	Share []byte `json:"share"`
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
	defer conn.Close()
	ctl, err := conn.Accept()
	if err != nil {
		return
	}
	rc := proto.NewRPCConn(ctl)
	ps.mu.Lock()
	ps.pairing = true
	ps.mu.Unlock()
	defer func() {
		ps.mu.Lock()
		ps.pairing = false
		ps.mu.Unlock()
	}()
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
	var peerName string
	rc.Handle("pair.request", func(params json.RawMessage) (any, error) {
		var p pairRequestParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		ps.mu.Lock()
		inv := ps.invite
		ps.mu.Unlock()
		if inv == nil || time.Now().After(inv.Expires) {
			return nil, errors.New("no pending pairing invite (generate one on this device)")
		}
		if p.Code != inv.Code {
			return nil, errors.New("wrong pairing code")
		}
		peerID := conn.RemoteID()
		s, err := identity.NewSPAKE2(identity.RoleVerifier, []byte(inv.Code),
			[]byte(peerID), []byte(ps.id.ID), conn.ChannelBinding())
		if err != nil {
			return nil, err
		}
		spk = s
		y, err := spk.CreateShare()
		if err != nil {
			return nil, err
		}
		confirm, err := spk.Finish(p.Share)
		if err != nil {
			return nil, err
		}
		peerName = p.Name
		return pairRequestResult{Name: ps.store.Get().Name, Share: y, Confirm: confirm}, nil
	})
	rc.Handle("pair.confirm", func(params json.RawMessage) (any, error) {
		if spk == nil {
			return nil, errors.New("pair.request first")
		}
		var p pairConfirmParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if err := spk.VerifyConfirm(p.Confirm); err != nil {
			return nil, err
		}
		// Mutual confirmation succeeded: pin the peer.
		peerID := conn.RemoteID()
		err := ps.store.UpsertPeer(config.Peer{
			ID:     peerID,
			Name:   peerName,
			PubKey: conn.RemotePub(),
			LastAddr: addrOf(conn),
		})
		if err != nil {
			return nil, err
		}
		ps.log.Info("paired with device", "id", peerID, "name", peerName)
		// Invalidate the invite (single use).
		ps.mu.Lock()
		ps.invite = nil
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
