// Command termprobe is a diagnostic tool: opens a terminal session on a
// peer through the daemon's web API, runs one command and prints the output.
// Used for automated e2e testing of the terminal path.
package main

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	// args: webPort token peer command
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: termprobe <webPort> <token> <peer> <command>")
		os.Exit(2)
	}
	port, tok, peer, cmd := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	u := fmt.Sprintf("ws://127.0.0.1:%s/api/term/ws?peer=%s&cols=100&rows=30&t=%s",
		port, url.QueryEscape(peer), url.QueryEscape(tok))
	ws, err := websocket.Dial(u, "", fmt.Sprintf("http://127.0.0.1:%s", port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame

	out := make(chan []byte, 256)
	go func() {
		buf := make([]byte, 8<<10)
		for {
			n, err := ws.Read(buf)
			if n > 0 {
				out <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(out)
				return
			}
		}
	}()

	// Drain initial banner, then send the command and look for the prompt
	// returning with our marker.
	time.Sleep(800 * time.Millisecond)
	for len(out) > 0 {
		<-out
	}
	ws.Write([]byte(cmd + "\r\n"))

	deadline := time.Now().Add(12 * time.Second)
	var all []byte
	for time.Now().Before(deadline) {
		select {
		case b, ok := <-out:
			if !ok {
				goto done
			}
			all = append(all, b...)
		case <-time.After(100 * time.Millisecond):
		}
		if strings.Contains(string(all), "PROBE_DONE_") {
			time.Sleep(300 * time.Millisecond)
			for {
				select {
				case b, ok := <-out:
					if !ok {
						goto done
					}
					all = append(all, b...)
					continue
				default:
				}
				break
			}
			goto done
		}
	}
done:
	text := stripANSI(string(all))
	fmt.Println(text)
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]|\r`)
	return re.ReplaceAllString(s, "")
}
