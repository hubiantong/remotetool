// Command hub is the self-hosted rendezvous + relay server for remotetool.
// Deploy it on any cheap VPS; devices configure it via their hub address.
// It sees only device ids and encrypted relay bytes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"remotetool/internal/hub"
	"remotetool/internal/identity"
	"remotetool/internal/transport"
)

var version = "0.1.0"

func main() {
	listen := flag.String("listen", ":27190", "QUIC listen address")
	token := flag.String("token", "", "shared token devices must present (recommended)")
	dir := flag.String("dir", "", "data directory for the hub certificate (default ./hubdata)")
	verbose := flag.Bool("v", false, "verbose logging")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Println("hub", version)
		return
	}

	dataDir := *dir
	if dataDir == "" {
		dataDir = "hubdata"
	}
	id, err := identity.LoadOrCreate(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hub:", err)
		os.Exit(1)
	}

	log := newLogger(*verbose)
	srv := hub.NewServer(*token, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tlsCfg := id.TLSConfig(nil)
	tlsCfg.NextProtos = []string{"rtd-hub/1"}
	ln, err := transport.Listen(*listen, tlsCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hub listen:", err)
		os.Exit(1)
	}
	log.Info("hub listening", "addr", *listen, "device", id.ID)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ln) }()
	select {
	case <-ctx.Done():
		_ = ln.Close()
		log.Info("hub stopped")
	case err := <-errCh:
		if err != nil {
			fmt.Fprintln(os.Stderr, "hub:", err)
			os.Exit(1)
		}
	}
}

func newLogger(verbose bool) *slog.Logger {
	opts := &slog.HandlerOptions{}
	if verbose {
		opts.Level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
