// Package proto defines the wire framing shared by all features: JSON control
// messages on the control stream and tiny binary headers on data streams.
//
// The layout mirrors UU远程's channel split (see D:\project\uu reverse-
// engineering reports): small JSON signalling + high-throughput binary data
// streams, replacing their WebRTC DataChannel with QUIC streams.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Chan is the channel type carried as the first byte of every data stream.
type Chan byte

const (
	ChanTerm Chan = 2 // bidirectional PTY bytes
	ChanFile Chan = 3 // transfer chunk stream
	ChanFwd  Chan = 4 // one forwarded TCP connection
)

// MaxMessage caps control-stream frames.
const MaxMessage = 4 << 20 // 4 MiB

// Message is one frame on the control stream.
type Message struct {
	ID     uint64          `json:"id,omitempty"`
	Method string          `json:"m,omitempty"`
	OK     bool            `json:"ok,omitempty"`
	Err    string          `json:"e,omitempty"`
	Params json.RawMessage `json:"p,omitempty"`
	Result json.RawMessage `json:"r,omitempty"`
}

// ReadMessage reads one length-prefixed control message.
func ReadMessage(r io.Reader) (*Message, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > MaxMessage {
		return nil, fmt.Errorf("control message too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	m := &Message{}
	if err := json.Unmarshal(buf, m); err != nil {
		return nil, fmt.Errorf("decode control message: %w", err)
	}
	return m, nil
}

// WriteMessage writes one length-prefixed control message.
func WriteMessage(w io.Writer, m *Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("control message too large: %d", len(b))
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// DataHeader follows the channel byte on every data stream and selects the
// logical flow inside that stream.
type DataHeader struct {
	Session uint64 `json:"s,omitempty"` // terminal session id
	XferID  string `json:"x,omitempty"` // file transfer id
	RuleID  string `json:"f,omitempty"` // fwd rule id (reverse mode)
	Dial    string `json:"d,omitempty"` // host:port to dial on the receiving side
	Mode    string `json:"mode,omitempty"`
}

// ReadDataHeader reads chan byte + JSON header.
func ReadDataHeader(r io.Reader) (Chan, *DataHeader, error) {
	var cb [1]byte
	if _, err := io.ReadFull(r, cb[:]); err != nil {
		return 0, nil, err
	}
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 64<<10 {
		return 0, nil, fmt.Errorf("data header too large: %d", n)
	}
	h := &DataHeader{}
	if n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
		if err := json.Unmarshal(buf, h); err != nil {
			return 0, nil, fmt.Errorf("decode data header: %w", err)
		}
	}
	return Chan(cb[0]), h, nil
}

// WriteDataHeader writes chan byte + JSON header.
func WriteDataHeader(w io.Writer, ch Chan, h *DataHeader) error {
	if _, err := w.Write([]byte{byte(ch)}); err != nil {
		return err
	}
	var buf []byte
	if h != nil {
		var err error
		buf, err = json.Marshal(h)
		if err != nil {
			return err
		}
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(buf)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	if len(buf) > 0 {
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}
