//go:build !windows

// Package term provides remote terminal sessions backed by real PTYs.
// Unix backend: fork/exec with a pty (creack/pty).
package term

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// PTY is one shell session pseudoterminal.
type PTY interface {
	io.ReadWriteCloser
	Resize(cols, rows uint16) error
	Kill() error
	Wait() (int, error)
}

// DefaultShell picks the login shell.
func DefaultShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "/bin/sh"
}

type unixPTY struct {
	f     *os.File
	cmd   *exec.Cmd
	once  sync.Once
	code  int
	errCh chan error
}

// StartPTY launches a shell on a fresh pty.
func StartPTY(cols, rows uint16, shell, cwd string) (PTY, error) {
	if shell == "" {
		shell = DefaultShell()
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	if cwd != "" {
		cmd.Dir = cwd
	}
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, err
	}
	// The pty handles SIGTTOU/SIGTTIN internally; keep the child in our group.
	up := &unixPTY{f: f, cmd: cmd, errCh: make(chan error, 1)}
	return up, nil
}

func (u *unixPTY) Read(p []byte) (int, error)  { return u.f.Read(p) }
func (u *unixPTY) Write(p []byte) (int, error) { return u.f.Write(p) }

func (u *unixPTY) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return nil
	}
	return pty.Setsize(u.f, &pty.Winsize{Cols: cols, Rows: rows})
}

func (u *unixPTY) Kill() error {
	if u.cmd.Process == nil {
		return nil
	}
	_ = u.cmd.Process.Kill()
	// Kill the whole process group if we are the leader (best effort).
	_ = u.cmd.Process.Release()
	return nil
}

func (u *unixPTY) Wait() (int, error) {
	u.once.Do(func() {
		err := u.cmd.Wait()
		u.code = 0
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				u.code = ee.ExitCode()
			} else {
				u.errCh <- err
			}
		}
		close(u.errCh)
	})
	return u.code, nil
}

func (u *unixPTY) Close() error {
	_ = u.Kill()
	return u.f.Close()
}
