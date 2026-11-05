package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindsDependencyWithoutExposingCredentials(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "app.py"), []byte("endpoint = 'https://user:secret@example.com/path?token=private'\nmodel.from_pretrained('model')\n"), 0600)
	findings, gaps := Scan(dir)
	if len(findings) != 2 || len(gaps) != 0 {
		t.Fatal(findings, gaps)
	}
	b, _ := json.Marshal(findings)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "private") {
		t.Fatal("credential leakage")
	}
	if findings[0].Line != 1 || findings[1].Line != 2 {
		t.Fatal("source location missing")
	}
}
