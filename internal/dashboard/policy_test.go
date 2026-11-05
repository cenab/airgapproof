package dashboard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/cenab/airgapproof/internal/report"
	"strings"
	"testing"
)

func evidence() *report.Report {
	r := report.New("demo", "developer", "compose", strings.Repeat("a", 64))
	r.Isolation.Verified = true
	r.Scenarios = []report.Scenario{{Name: "workflow", Passed: true}}
	r.Finish(1)
	return r
}
func TestPolicyEnforcesTrustIsolationAndCoverage(t *testing.T) {
	r := evidence()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	p := Policy{RequireDisconnected: true, RequireTracing: true, RequireSignature: true, TrustedKeys: []string{base64.StdEncoding.EncodeToString(pub)}, MinScenarios: 1}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Evaluate(r).Passed {
		t.Fatal("untrusted developer evidence passed")
	}
	r.Isolation.Mode = "disconnected"
	r.Isolation.Tracing = true
	_ = r.Sign(key)
	if !p.Evaluate(r).Passed {
		t.Fatal(p.Evaluate(r))
	}
	r.Scenarios[0].Passed = false
	if p.Evaluate(r).Passed {
		t.Fatal("tamper passed")
	}
}
func TestPolicyAttemptsAndComparison(t *testing.T) {
	base := evidence()
	head := evidence()
	head.Status = "not_ready"
	head.Scenarios[0].Passed = false
	head.Observations = []report.Observation{{External: true}}
	if (Policy{FailOnAttempts: true}).Evaluate(head).Passed {
		t.Fatal("egress accepted")
	}
	c := Compare(base, head)
	if len(c.Changes) != 2 || !c.SameProfile {
		t.Fatal(c)
	}
}
func TestComparisonDeduplicatesRepeatedFindings(t *testing.T) {
	base, head := evidence(), evidence()
	f := report.Finding{Rule: "static.external-url", Path: "app.py", Line: 1}
	base.Findings = []report.Finding{f}
	head.Findings = []report.Finding{f, f}
	c := Compare(base, head)
	if len(c.AddedFindings) > 0 || len(c.ResolvedFindings) > 0 {
		t.Fatal(c)
	}
}
