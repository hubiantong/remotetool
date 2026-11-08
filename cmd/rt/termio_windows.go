//go:build windows

package main

import (
	"time"

	"golang.org/x/net/websocket"
	"golang.org/x/sys/windows"
)

const enableVirtualTerminalProcessing = 0x0004

func init() {
	// Enable ANSI escape processing on stdout for xterm.js-compatible output.
	var mode uint32
	h := windows.Handle(windows.STD_OUTPUT_HANDLE)
	if err := windows.GetConsoleMode(h, &mode); err == nil {
		_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalProcessing)
	}
}

func winConsoleSize() (uint16, uint16) {
	var info windows.ConsoleScreenBufferInfo
	h := windows.Handle(windows.STD_OUTPUT_HANDLE)
	if err := windows.GetConsoleScreenBufferInfo(h, &info); err != nil {
		return 0, 0
	}
	w := uint16(info.Window.Right-info.Window.Left) + 1
	ht := uint16(info.Window.Bottom-info.Window.Top) + 1
	return w, ht
}

// watchResize polls the console size (no SIGWINCH on Windows).
func watchResize(ws *websocket.Conn) {
	lastC, lastR := winConsoleSize()
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			c, r := winConsoleSize()
			if c > 0 && r > 0 && (c != lastC || r != lastR) {
				lastC, lastR = c, r
				sendResize(ws, c, r)
			}
		}
	}()
}
