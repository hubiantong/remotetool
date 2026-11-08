// Command rt is the CLI companion to a running rtd daemon. It talks to the
// daemon's local web API (never dials peers directly, so peer connections
// stay owned by the daemon).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"remotetool/internal/config"
)

// version is a var so build.sh's -ldflags "-X main.version=..." can stamp
// the real version (git describe) at link time; a const would ignore it.
var version = "0.1.0"

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	cmd := flag.Arg(0)
	args := flag.Args()[1:]
	var err error
	switch cmd {
	case "status":
		err = cmdStatus()
	case "url":
		err = cmdURL()
	case "pair":
		err = cmdPair(args)
	case "ls":
		err = cmdLs()
	case "term":
		err = cmdTerm(args)
	case "cp":
		err = cmdCp(args)
	case "fwd":
		err = cmdFwd(args)
	case "hub":
		err = cmdHub(args)
	case "version":
		fmt.Println("rt", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rt:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`rt - remotetool CLI

Usage:
  rt status                     show this device and peers
  rt url                        print the web UI URL
  rt pair                       generate a pairing code (run on the device to be trusted)
  rt pair <addr> <code>         pair with a device using its code
  rt ls                         list paired / connected / nearby devices
  rt term <device>              open a remote terminal
  rt cp <src> <dst>             copy files; one side is <device>:<path>
  rt fwd list | add | rm        manage port forwards
  rt hub <addr> [token]         point this device at a self-hosted hub ("" to clear)
  rt version

Examples:
  rt cp ./big.zip desktop:Downloads/big.zip
  rt cp desktop:C:/data/report.docx ./
  rt fwd add desktop -L 13389:localhost:3389
  rt fwd add desktop -R 9090:localhost:8080
`)
}

// ---------------------------------------------------------------- client ---

type client struct {
	base string
	tok  string
	hc   *http.Client
}

func newClient() (*client, error) {
	store, err := config.Open(config.DefaultDir())
	if err != nil {
		return nil, err
	}
	cfg := store.Get()
	return &client{
		base: fmt.Sprintf("http://127.0.0.1:%d", cfg.WebPort),
		tok:  cfg.WebToken,
		hc:   &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *client) do(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-RT-Token", c.tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon unreachable (is rtd running?): %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return b, nil
}

func (c *client) getJSON(path string, out any) error {
	b, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (c *client) postJSON(path string, body, out any) error {
	b, err := c.do(http.MethodPost, path, body)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---------------------------------------------------------------- status ---

func cmdStatus() error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var st struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Port      int    `json:"port"`
		WebPort   int    `json:"web_port"`
		Connected []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Addr string `json:"addr"`
		} `json:"connected"`
		Peers []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			LastAddr string `json:"last_addr"`
			LastSeen string `json:"last_seen"`
		} `json:"peers"`
	}
	if err := c.getJSON("/api/status", &st); err != nil {
		return err
	}
	fmt.Printf("device: %s (%s)\n", st.Name, shortID(st.ID))
	fmt.Printf("listen: :%d   web: http://127.0.0.1:%d\n", st.Port, st.WebPort)
	online := map[string]bool{}
	for _, cn := range st.Connected {
		online[cn.ID] = true
		fmt.Printf("  [online] %s (%s) via %s\n", cn.Name, shortID(cn.ID), cn.Addr)
	}
	for _, p := range st.Peers {
		if online[p.ID] {
			continue
		}
		last := p.LastSeen
		if t, err := time.Parse(time.RFC3339, last); err == nil {
			last = t.Local().Format("2006-01-02 15:04")
		}
		fmt.Printf("  [offline] %s (%s) last %s\n", p.Name, shortID(p.ID), last)
	}
	if len(st.Peers) == 0 && len(st.Connected) == 0 {
		fmt.Println("  no paired devices yet — run `rt pair` here, then `rt pair <addr> <code>` on the other device")
	}
	return nil
}

func cmdURL() error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var st struct {
		WebPort int `json:"web_port"`
	}
	if err := c.getJSON("/api/status", &st); err != nil {
		return err
	}
	fmt.Printf("http://127.0.0.1:%d/?t=%s\n", st.WebPort, c.tok)
	return nil
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// ------------------------------------------------------------------ pair ---

func cmdPair(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		var res struct {
			Code    string `json:"code"`
			Expires int64  `json:"expires"`
		}
		if err := c.postJSON("/api/pair/invite", map[string]any{}, &res); err != nil {
			return err
		}
		exp := time.UnixMilli(res.Expires).Format("15:04")
		fmt.Printf("pairing code: %s  (valid until %s)\n", res.Code, exp)
		fmt.Println("on the other device run:  rt pair <this-addr> " + res.Code)
		fmt.Println("or open this device's web UI: Devices -> Pair")
		return nil
	}
	if len(args) != 2 {
		return fmt.Errorf("usage: rt pair <addr:port> <code>")
	}
	var res struct {
		Peer struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"peer"`
	}
	if err := c.postJSON("/api/pair/connect", map[string]string{"addr": args[0], "code": args[1]}, &res); err != nil {
		return err
	}
	fmt.Printf("paired with %s (%s)\n", res.Peer.Name, shortID(res.Peer.ID))
	return nil
}

// -------------------------------------------------------------------- ls ---

func cmdLs() error { return cmdStatus() }

// ------------------------------------------------------------------ term ---

func cmdTerm(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: rt term <device>")
	}
	peer := args[0]
	c, err := newClient()
	if err != nil {
		return err
	}
	restore, cols, rows, err := makeRaw()
	if err != nil {
		return fmt.Errorf("terminal: %w", err)
	}
	defer restore()

	u := fmt.Sprintf("ws://127.0.0.1:%s/api/term/ws?peer=%s&cols=%d&rows=%d&t=%s",
		strings.SplitN(c.base[7:], ":", 2)[1], url.QueryEscape(peer), cols, rows, c.tok)
	return runTermWS(u)
}

// -------------------------------------------------------------------- cp ---

func cmdCp(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: rt cp <src> <dst>   (one side as <device>:<path>)")
	}
	src, dst := args[0], args[1]
	// Fast path: without any colon neither side can name a remote device, so
	// report the usage error without a daemon round-trip.
	if !strings.Contains(src, ":") && !strings.Contains(dst, ":") {
		return fmt.Errorf("exactly one side must be <device>:<path>")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	// A side is remote only when the text before its first colon names a
	// paired device; a Windows local path (C:\data\f.zip) matches no device
	// and stays local.
	srcDev, srcPath, srcRemote := resolveRemotePrefix(c, src)
	dstDev, dstPath, dstRemote := resolveRemotePrefix(c, dst)
	if srcRemote == dstRemote {
		return fmt.Errorf("exactly one side must be <device>:<path>")
	}
	var res struct {
		OK bool   `json:"ok"`
		ID string `json:"id"` // transfer id ("" on older daemons: watch all)
	}
	if dstRemote {
		err = c.postJSON("/api/xfer/push", map[string]string{
			"peer": dstDev, "local": src, "remote": dstPath, "conflict": "rename",
		}, &res)
	} else {
		err = c.postJSON("/api/xfer/pull", map[string]string{
			"peer": srcDev, "remote": srcPath, "local": dst, "conflict": "rename",
		}, &res)
	}
	if err != nil {
		return err
	}
	return watchProgress(c, res.ID)
}

// peerEntry is one paired/connected device as reported by /api/status.
type peerEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listPeers fetches the known devices from the daemon.
func listPeers(c *client) ([]peerEntry, error) {
	var st struct {
		Connected []peerEntry `json:"connected"`
		Peers     []peerEntry `json:"peers"`
	}
	if err := c.getJSON("/api/status", &st); err != nil {
		return nil, err
	}
	out := make([]peerEntry, 0, len(st.Peers)+len(st.Connected))
	seen := map[string]bool{}
	for _, p := range append(st.Connected, st.Peers...) {
		if p.ID == "" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out, nil
}

// resolveRemotePrefix decides whether s is "<device>:<remote path>" and
// splits it. The candidate prefix (text before the first colon) counts as a
// device only if it matches a paired device's name exactly (case-insensitive)
// or is a prefix of its device id. A single-letter candidate is treated as a
// Windows drive letter and never matches an id prefix (hex ids can start
// with any letter, so "C:\..." must not match an id starting with 'c').
// ok is false when s is local — or when the peer list cannot be fetched.
func resolveRemotePrefix(c *client, s string) (dev, rest string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	prefix, rest := s[:i], s[i+1:]
	peers, err := listPeers(c)
	if err != nil {
		return "", "", false
	}
	for _, p := range peers {
		if p.Name != "" && strings.EqualFold(prefix, p.Name) {
			return prefix, rest, true
		}
	}
	if len(prefix) > 1 {
		for _, p := range peers {
			if strings.HasPrefix(strings.ToLower(p.ID), strings.ToLower(prefix)) {
				return prefix, rest, true
			}
		}
	}
	return "", "", false
}

// sseClient has no global Timeout: /api/events is a long-lived SSE stream and
// the 60s default client timeout would abort it mid-transfer.
var sseClient = &http.Client{}

// watchProgress reads the SSE stream and prints transfer events. When xferID
// is non-empty only events for that transfer are shown, so a concurrent
// `rt cp` on the same daemon cannot terminate this one early; an empty
// xferID (older daemon, directory push) watches every transfer.
func watchProgress(c *client, xferID string) error {
	eventsURL := c.base + "/api/events?t=" + url.QueryEscape(c.tok)
	if xferID != "" {
		// Ask the daemon to replay this transfer's latest event on connect:
		// a fast transfer may be finished before the subscription attaches.
		eventsURL += "&xfer=" + url.QueryEscape(xferID)
	}
	req, _ := http.NewRequest(http.MethodGet, eventsURL, nil)
	resp, err := sseClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Println("transferring... (Ctrl+C to detach; transfer continues on the daemon)")
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	last := ""
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev struct {
			Type string `json:"type"`
			Data struct {
				ID        string `json:"id"`
				Direction string `json:"direction"`
				Name      string `json:"name"`
				Size      int64  `json:"size"`
				Done      int64  `json:"done"`
				State     string `json:"state"`
				Err       string `json:"err"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(line[6:]), &ev) != nil || ev.Type != "xfer" {
			continue
		}
		if xferID != "" && ev.Data.ID != xferID {
			continue
		}
		pct := ""
		if ev.Data.Size > 0 {
			pct = fmt.Sprintf(" %3.0f%%", 100*float64(ev.Data.Done)/float64(ev.Data.Size))
		} else if ev.Data.Done > 0 {
			pct = fmt.Sprintf(" %s", humanBytes(ev.Data.Done))
		}
		status := ev.Data.State
		if status == "running" {
			status = ""
		}
		out := fmt.Sprintf("\r%s: %s%s %s\033[K", ev.Data.Direction, ev.Data.Name, pct, status)
		if ev.Data.Err != "" {
			out += " " + ev.Data.Err
		}
		if out != last {
			fmt.Print(out)
			last = out
		}
		if ev.Data.State == "done" || ev.Data.State == "error" {
			fmt.Println()
			if ev.Data.State == "error" {
				return fmt.Errorf("%s", ev.Data.Err)
			}
			return nil
		}
	}
	return sc.Err()
}

func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1fGB", float64(n)/k/k/k)
	case n >= k*k:
		return fmt.Sprintf("%.1fMB", float64(n)/k/k)
	case n >= k:
		return fmt.Sprintf("%.1fKB", float64(n)/k)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// ------------------------------------------------------------------ hub ---

func cmdHub(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if len(args) < 1 {
		var st struct {
			HubAddr string `json:"hub_addr"`
		}
		if err := c.getJSON("/api/status", &st); err != nil {
			return err
		}
		if st.HubAddr == "" {
			fmt.Println("no hub configured")
		} else {
			fmt.Println("hub:", st.HubAddr)
		}
		return nil
	}
	return c.postJSON("/api/hub", map[string]string{"addr": args[0], "token": strings.Join(args[1:], " ")}, nil)
}

// ------------------------------------------------------------------ fwd ---

func cmdFwd(args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "list" {
		var res struct {
			Rules []struct {
				ID         string `json:"id"`
				PeerID     string `json:"peer_id"`
				Mode       string `json:"mode"`
				ListenHost string `json:"listen_host"`
				ListenPort int    `json:"listen_port"`
				TargetHost string `json:"target_host"`
				TargetPort int    `json:"target_port"`
			} `json:"rules"`
			Active map[string]bool `json:"active"`
		}
		if err := c.getJSON("/api/fwd", &res); err != nil {
			return err
		}
		if len(res.Rules) == 0 {
			fmt.Println("no forwarding rules")
			return nil
		}
		for _, r := range res.Rules {
			state := "off"
			if res.Active[r.ID] {
				state = "active"
			}
			fmt.Printf("  [%s] %s  -%s %s:%d -> %s:%d\n",
				state, shortID(r.PeerID), strings.ToLower(r.Mode),
				orDefault(r.ListenHost, "127.0.0.1"), r.ListenPort,
				r.TargetHost, r.TargetPort)
		}
		return nil
	}
	if args[0] == "add" {
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		local := fs.String("L", "", "listen here: [host:]port:targetHost:targetPort")
		remote := fs.String("R", "", "peer listens: [host:]port:targetHost:targetPort")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: rt fwd add <device> -L port:targetHost:targetPort | -R ...")
		}
		spec, mode := *local, "L"
		if *remote != "" {
			if *local != "" {
				return fmt.Errorf("use either -L or -R, not both")
			}
			spec, mode = *remote, "R"
		}
		rule, err := parseFwdSpec(spec, mode, fs.Arg(0))
		if err != nil {
			return err
		}
		return c.postJSON("/api/fwd/add", rule, nil)
	}
	if args[0] == "rm" || args[0] == "remove" {
		if len(args) != 2 {
			return fmt.Errorf("usage: rt fwd rm <id>")
		}
		return c.postJSON("/api/fwd/remove", map[string]string{"id": args[1]}, nil)
	}
	return fmt.Errorf("unknown fwd command %q", args[0])
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// parseFwdSpec parses [host:]port:targetHost:targetPort.
func parseFwdSpec(spec, mode, peer string) (map[string]any, error) {
	parts := strings.Split(spec, ":")
	var listenHost, listenPort, targetHost, targetPort string
	switch len(parts) {
	case 3:
		listenHost, listenPort, targetHost, targetPort = "127.0.0.1", parts[0], parts[1], parts[2]
	case 4:
		listenHost, listenPort, targetHost, targetPort = parts[0], parts[1], parts[2], parts[3]
	default:
		return nil, fmt.Errorf("bad forward spec %q (want [host:]port:targetHost:targetPort)", spec)
	}
	lp, err := strconv.Atoi(listenPort)
	if err != nil {
		return nil, fmt.Errorf("bad listen port %q", listenPort)
	}
	tp, err := strconv.Atoi(targetPort)
	if err != nil {
		return nil, fmt.Errorf("bad target port %q", targetPort)
	}
	return map[string]any{
		"peer_id":     peer,
		"mode":        mode,
		"listen_host": listenHost,
		"listen_port": lp,
		"target_host": targetHost,
		"target_port": tp,
	}, nil
}
