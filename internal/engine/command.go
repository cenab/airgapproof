package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LimitedBuffer consumes all output without retaining unbounded application data.
type LimitedBuffer struct {
	bytes.Buffer
	Limit int
}
type CommandError struct {
	Name       string
	Cause      error
	Diagnostic string
}

func (e *CommandError) Error() string { return fmt.Sprintf("%s failed: %v", e.Name, e.Cause) }
func (e *CommandError) Unwrap() error { return e.Cause }
func Diagnostic(err error) string {
	var e *CommandError
	if errors.As(err, &e) {
		return e.Diagnostic
	}
	return ""
}

func (b *LimitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := b.Limit - b.Len()
	if left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func Run(ctx context.Context, input io.Reader, name string, args ...string) ([]byte, error) {
	return RunEnv(ctx, input, nil, name, args...)
}
func RunEnv(ctx context.Context, input io.Reader, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = input
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out := &LimitedBuffer{Limit: 16 << 20}
	stderr := &LimitedBuffer{Limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return out.Bytes(), ctx.Err()
		}
		return out.Bytes(), &CommandError{Name: name + " " + operation(args), Cause: err, Diagnostic: stderr.String()}
	}
	return out.Bytes(), nil
}
func operation(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *exec.ExitError
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -1
}
func Docker(ctx context.Context, args ...string) ([]byte, error) {
	return Run(ctx, nil, "docker", args...)
}
func WritePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".airgapproof-write-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func Lines(b []byte) []string { return strings.Fields(string(b)) }
