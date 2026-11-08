package proto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Handler serves one control method. Returned values are JSON-encoded as the
// response result.
type Handler func(params json.RawMessage) (any, error)

// RPCConn multiplexes request/response over a single control stream.
type RPCConn struct {
	rwc       io.ReadWriteCloser
	writeMu   sync.Mutex
	nextID    atomic.Uint64
	mu        sync.Mutex
	pending   map[uint64]chan *Message
	handlers  sync.Map
	closed    chan struct{}
	closeOnce sync.Once

	// OnNotify receives unsolicited peer messages (method != "", ID == 0).
	OnNotify func(method string, params json.RawMessage)
}

// NewRPCConn wraps a control stream.
func NewRPCConn(rwc io.ReadWriteCloser) *RPCConn {
	return &RPCConn{
		rwc:     rwc,
		pending: map[uint64]chan *Message{},
		closed:  make(chan struct{}),
	}
}

// Handle registers a server-side method handler.
func (c *RPCConn) Handle(method string, h Handler) { c.handlers.Store(method, h) }

// Serve runs the read loop until the stream closes or Close is called.
// Request handling runs on one goroutine per request.
func (c *RPCConn) Serve() {
	for {
		m, err := ReadMessage(c.rwc)
		if err != nil {
			c.Close()
			return
		}
		switch {
		case m.ID != 0 && m.Method == "":
			c.mu.Lock()
			ch, ok := c.pending[m.ID]
			if ok {
				delete(c.pending, m.ID)
			}
			c.mu.Unlock()
			if ok {
				select {
				case ch <- m:
				case <-c.closed:
				}
			}
		case m.Method != "" && m.ID != 0:
			// Request: dispatch on its own goroutine so slow handlers do not
			// block the stream.
			go c.serveRequest(m)
		case m.Method != "" && m.ID == 0:
			if c.OnNotify != nil {
				c.OnNotify(m.Method, m.Params)
			}
		}
		select {
		case <-c.closed:
			return
		default:
		}
	}
}

func (c *RPCConn) serveRequest(m *Message) {
	var resp *Message
	if h, ok := c.handlers.Load(m.Method); ok {
		result, err := h.(Handler)(m.Params)
		if err != nil {
			resp = &Message{ID: m.ID, OK: false, Err: err.Error()}
		} else {
			raw, jerr := json.Marshal(result)
			if jerr != nil {
				resp = &Message{ID: m.ID, OK: false, Err: jerr.Error()}
			} else {
				resp = &Message{ID: m.ID, OK: true, Result: raw}
			}
		}
	} else {
		resp = &Message{ID: m.ID, OK: false, Err: "no handler for " + m.Method}
	}
	if err := c.write(resp); err != nil {
		c.Close()
	}
}

func (c *RPCConn) write(m *Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteMessage(c.rwc, m)
}

// Call performs a request/response round-trip.
func (c *RPCConn) Call(ctx context.Context, method string, params, result any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	id := c.nextID.Add(1)
	ch := make(chan *Message, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.write(&Message{ID: id, Method: method, Params: raw}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}
	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	case <-c.closed:
		return errors.New("connection closed")
	case resp := <-ch:
		if !resp.OK {
			return fmt.Errorf("%s: %s", method, resp.Err)
		}
		if result != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	}
}

// Notify sends an unsolicited message without expecting a reply.
func (c *RPCConn) Notify(method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	return c.write(&Message{Method: method, Params: raw})
}

// Close shuts the control stream down.
func (c *RPCConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.rwc.Close()
	})
	return nil
}

// Done exposes the closed channel.
func (c *RPCConn) Done() <-chan struct{} { return c.closed }
