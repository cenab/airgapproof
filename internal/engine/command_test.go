package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateWritesReplaceSymlinksWithoutFollowingThem(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "output")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(link, []byte("report")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "original" {
		t.Fatal("target overwritten")
	}
	b, _ = os.ReadFile(link)
	if string(b) != "report" {
		t.Fatal("output not replaced")
	}
}
func TestBoundedOutputStillConsumesAllBytes(t *testing.T) {
	b := &LimitedBuffer{Limit: 3}
	if n, err := b.Write([]byte("123456")); n != 6 || err != nil || b.String() != "123" {
		t.Fatal(n, err, b.String())
	}
}

func TestCommandDiagnosticsAreBounded(t *testing.T) {
	_, err := Run(context.Background(), strings.NewReader(strings.Repeat("x", 8192)), "sh", "-c", "cat >&2; exit 1")
	if ExitCode(err) != 1 || len(Diagnostic(err)) != 4096 {
		t.Fatalf("exit=%d diagnostic bytes=%d", ExitCode(err), len(Diagnostic(err)))
	}
}
