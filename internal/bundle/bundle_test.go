package bundle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := Manifest{Version: 1, Images: []Image{{Reference: "demo:local", ID: "sha256:abc"}}}
	for _, name := range []string{"airgapproof.yaml", "images.tar"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
		hash, n, err := HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m.Files = append(m.Files, File{Path: name, SHA256: hash, Size: n})
	}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestLoadUsesContentIdentityWithoutRegistryMetadata(t *testing.T) {
	dir := fixture(t)
	tools := t.TempDir()
	script := `#!/bin/sh
if [ "$1 $2" = "image load" ]; then exit 0; fi
if [ "$1 $2" = "image inspect" ] && [ "$5" = "sha256:abc" ]; then printf '%s\n' 'sha256:abc'; exit 0; fi
if [ "$1 $2" = "image tag" ] && [ "$3" = "sha256:abc" ] && [ "$4" = "airgapproof.local/image:abc" ]; then exit 0; fi
exit 1
`
	if err := os.WriteFile(filepath.Join(tools, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := Load(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
}
func TestVerifyTamperingAndExtraFiles(t *testing.T) {
	dir := fixture(t)
	if _, err := Verify(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images.tar"), []byte("tamper"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil {
		t.Fatal("tamper accepted")
	}
	dir = fixture(t)
	_ = os.WriteFile(filepath.Join(dir, "unlisted"), nil, 0600)
	if _, err := Verify(dir); err == nil {
		t.Fatal("unlisted file accepted")
	}
}
func TestVerifyRejectsSymlinksAndTraversal(t *testing.T) {
	dir := fixture(t)
	path := filepath.Join(dir, "images.tar")
	_ = os.Remove(path)
	_ = os.Symlink("/etc/hosts", path)
	if _, err := Verify(dir); err == nil {
		t.Fatal("symlink accepted")
	}
	dir = fixture(t)
	b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var m Manifest
	_ = json.Unmarshal(b, &m)
	m.Files[0].Path = "../secret"
	b, _ = json.Marshal(m)
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600)
	if _, err := Verify(dir); err == nil {
		t.Fatal("traversal accepted")
	}
}
