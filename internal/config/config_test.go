package config

import (
	"strings"
	"testing"
)

const valid = `version: 1
application:
  compose: compose.yaml
scenarios:
  - name: health
    type: http
    url: http://api:8080/health
`

func TestStrictProfile(t *testing.T) {
	for _, input := range []string{valid + "unknown: true\n", valid + "---\nversion: 1\n", strings.Replace(valid, "version: 1", "version: 99", 1), valid + "isolation:\n  deny_external_network: false\n", strings.Replace(valid, "type: http", "type: unknown", 1), strings.Replace(valid, "http://api:8080/health", "http://secret:password@example.com", 1), valid + "artifacts:\n  require_preloaded_images: false\n"} {
		c, err := Parse([]byte(input))
		if err == nil {
			err = c.Validate()
		}
		if err == nil {
			t.Errorf("accepted invalid profile: %s", input)
		}
	}
	c, err := Parse([]byte(valid))
	if err != nil || c.Validate() != nil {
		t.Fatal(c, err)
	}
	if c.Scenarios[0].ExpectedStatus != 200 || c.Isolation.Mode != "developer" {
		t.Fatal("defaults missing")
	}
}
func TestRestartReference(t *testing.T) {
	c, _ := Parse([]byte(valid + "  - name: recovery\n    type: restart\n    service: api\n    verify: absent\n"))
	if c.Validate() == nil {
		t.Fatal("accepted unknown recovery verification")
	}
}
func TestSafePaths(t *testing.T) {
	for _, p := range []string{"../secret", "/etc/shadow", "..", "a/../../secret", "a\\b"} {
		if SafeRelative(p) {
			t.Fatal(p)
		}
	}
	if !SafeRelative("models/weights.bin") {
		t.Fatal("safe path rejected")
	}
}
