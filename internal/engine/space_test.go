//go:build linux || darwin

package engine

import (
	"strings"
	"testing"
)

func TestRequireSpace(t *testing.T) {
	dir := t.TempDir()
	if err := RequireSpace(dir, 0); err != nil {
		t.Fatal(err)
	}
	if err := RequireSpace(dir, ^uint64(0)); err == nil || !strings.Contains(err.Error(), "insufficient disk space") {
		t.Fatalf("impossible allocation accepted: %v", err)
	}
	if err := RequireSpace(dir+"/missing", 0); err == nil {
		t.Fatal("missing filesystem path accepted")
	}
}
