package report

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignatureTamperAndTrust(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r := New("demo", "developer", "compose", strings.Repeat("a", 64))
	r.Isolation.Verified = true
	r.Scenarios = append(r.Scenarios, Scenario{Name: "health", Passed: true})
	r.Finish(1)
	if err := r.Sign(key); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	var roundtrip Report
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := roundtrip.Verify(pub); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if roundtrip.Verify(other) == nil {
		t.Fatal("untrusted signer accepted")
	}
	roundtrip.Application = "tampered"
	if roundtrip.Verify(pub) == nil {
		t.Fatal("tamper accepted")
	}
}
func TestReadinessRequiresEvidence(t *testing.T) {
	r := New("demo", "developer", "compose", strings.Repeat("a", 64))
	r.Scenarios = []Scenario{{Name: "health", Passed: true}}
	r.Finish(1)
	if r.Status == "ready" {
		t.Fatal("unverified isolation passed")
	}
	r.Isolation.Verified = true
	r.Finish(2)
	if r.Status == "ready" {
		t.Fatal("missing workflow passed")
	}
	r.Finish(1)
	if r.Status != "ready" || r.Validate() != nil {
		t.Fatal("valid evidence rejected")
	}
	r.Fail("failure", "functional", "api", "failed", "fix")
	r.Finish(1)
	if r.Status == "ready" {
		t.Fatal("error finding passed")
	}
}
func TestHTMLEscapesEvidence(t *testing.T) {
	r := New(`<script>alert(1)</script>`, "developer", "compose", strings.Repeat("a", 64))
	r.Findings = []Finding{{Rule: "test", Severity: "error", Message: `<img src=x onerror=alert(1)>`}}
	b, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "<script>") || strings.Contains(string(b), "<img src=x") {
		t.Fatal("unescaped evidence")
	}
	if _, err = json.Marshal(r.SARIF()); err != nil {
		t.Fatal(err)
	}
}
