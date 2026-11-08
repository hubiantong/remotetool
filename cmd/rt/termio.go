package main

import (
	"fmt"
	"os"

	"golang.org/x/net/websocket"
	"golang.org/x/term"
)

// runTermWS bridges local stdin/stdout to the daemon's terminal WebSocket.
func runTermWS(u string) error {
	ws, err := websocket.Dial(u, "", "http://127.0.0.1")
	if err != nil {
		return fmt.Errorf("terminal websocket: %w", err)
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame

	done := make(chan error, 2)
	// remote -> stdout
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := ws.Read(buf)
			if n > 0 {
				if _, werr := os.Stdout.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- nil // peer closed: normal exit
				return
			}
		}
	}()
	// stdin -> remote
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if _, werr := ws.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- nil
				return
			}
		}
	}()
	watchResize(ws)

	return <-done
}

func sendResize(ws *websocket.Conn, cols, rows uint16) {
	ws.PayloadType = websocket.TextFrame
	_, _ = ws.Write([]byte(fmt.Sprintf(`{"cols":%d,"rows":%d}`, cols, rows)))
}

// makeRaw switches the terminal to raw mode; returns restore func + size.
func makeRaw() (restore func(), cols, rows uint16, err error) {
	fd := os.Stdin.Fd()
	st, err := term.GetState(int(fd))
	if err != nil {
		return func() {}, 80, 24, nil
	}
	if _, err := term.MakeRaw(int(fd)); err != nil {
		return func() {}, 80, 24, err
	}
	w, h, _ := term.GetSize(int(fd))
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return func() { _ = term.Restore(int(fd), st) }, uint16(w), uint16(h), nil
}
