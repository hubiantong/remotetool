//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/websocket"
	"golang.org/x/term"
)

// watchResize reacts to SIGWINCH.
func watchResize(ws *websocket.Conn) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			w, h, err := term.GetSize(int(os.Stdin.Fd()))
			if err == nil && w > 0 && h > 0 {
				sendResize(ws, uint16(w), uint16(h))
			}
		}
	}()
}
