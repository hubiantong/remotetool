// Command rtd is the remotetool daemon: listener, pairing, terminal, file
// transfer, port forwarding and the local web UI.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"remotetool/internal/daemon"
)

func main() {
	home := flag.String("home", "", "config directory (default: per-OS app data dir)")
	name := flag.String("name", "", "device display name")
	listenPort := flag.Int("listen-port", 0, "QUIC listen port (default 27183)")
	webPort := flag.Int("web-port", 0, "web UI port (default 27180)")
	verbose := flag.Bool("v", false, "verbose logging")
	version := flag.Bool("version", false, "print version")
	flag.Parse()

	if *version {
		fmt.Println("rtd 0.1.0")
		return
	}

	d, err := daemon.New(daemon.Options{
		Home:       *home,
		Name:       *name,
		ListenPort: *listenPort,
		WebPort:    *webPort,
		Verbose:    *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "rtd:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := d.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "rtd:", err)
		os.Exit(1)
	}
}
