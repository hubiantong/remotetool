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

const version = "0.1.0"

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
	srcRemote := strings.Contains(src, ":")
	dstRemote := strings.Contains(dst, ":")
	if srcRemote == dstRemote {
		return fmt.Errorf("exactly one side must be <device>:<path>")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if dstRemote {
		dev, path := splitRemote(dst)
		err = c.postJSON("/api/xfer/push", map[string]string{
			"peer": dev, "local": src, "remote": path, "conflict": "rename",
		}, nil)
	} else {
		dev, path := splitRemote(src)
		err = c.postJSON("/api/xfer/pull", map[string]string{
			"peer": dev, "remote": path, "local": dst, "conflict": "rename",
		}, nil)
	}
	if err != nil {
		return err
	}
	return watchProgress(c)
}

func splitRemote(s string) (dev, path string) {
	i := strings.Index(s, ":")
	return s[:i], s[i+1:]
}

// watchProgress reads the SSE stream and prints transfer events.
func watchProgress(c *client) error {
	req, _ := http.NewRequest(http.MethodGet, c.base+"/api/events?t="+url.QueryEscape(c.tok), nil)
	resp, err := c.hc.Do(req)
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
