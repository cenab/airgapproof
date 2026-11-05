package dashboard

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/cenab/airgapproof/internal/report"
)

type Policy struct {
	RequireDisconnected bool     `json:"require_disconnected"`
	RequireTracing      bool     `json:"require_tracing"`
	FailOnAttempts      bool     `json:"fail_on_attempts"`
	MinScenarios        int      `json:"min_scenarios"`
	MaxWarnings         *int     `json:"max_warnings,omitempty"`
	RequireSignature    bool     `json:"require_signature"`
	TrustedKeys         []string `json:"trusted_keys,omitempty"`
}
type Decision struct {
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons"`
	Policy  Policy   `json:"policy"`
}

func (p Policy) Validate() error {
	if p.MinScenarios < 0 || (p.MaxWarnings != nil && *p.MaxWarnings < 0) {
		return fmt.Errorf("policy counts must not be negative")
	}
	if p.RequireSignature && len(p.TrustedKeys) == 0 {
		return fmt.Errorf("signature policy needs at least one trusted public key")
	}
	for _, s := range p.TrustedKeys {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("trusted_keys must contain base64 Ed25519 public keys")
		}
	}
	return nil
}
func (p Policy) Evaluate(r *report.Report) Decision {
	d := Decision{Passed: true, Reasons: []string{}, Policy: p}
	fail := func(s string) { d.Passed = false; d.Reasons = append(d.Reasons, s) }
	if err := r.Validate(); err != nil {
		fail(err.Error())
	}
	if r.Status != "ready" {
		fail("Report is not ready")
	}
	if p.RequireDisconnected && r.Isolation.Mode != "disconnected" {
		fail("Disconnected VM isolation is required")
	}
	if p.RequireTracing && !r.Isolation.Tracing {
		fail("Runtime syscall tracing is required")
	}
	if len(r.Scenarios) < p.MinScenarios {
		fail("Insufficient functional scenarios")
	}
	warnings := 0
	for _, f := range r.Findings {
		if f.Severity == "warning" {
			warnings++
		}
	}
	if p.MaxWarnings != nil && warnings > *p.MaxWarnings {
		fail("Warning limit exceeded")
	}
	if p.FailOnAttempts {
		for _, o := range r.Observations {
			if o.External {
				fail("External access attempts are forbidden")
				break
			}
		}
	}
	if r.Signature != nil {
		if err := r.Verify(nil); err != nil {
			fail("Report signature is invalid")
		}
	}
	if p.RequireSignature {
		trusted := false
		for _, s := range p.TrustedKeys {
			b, _ := base64.StdEncoding.DecodeString(s)
			if r.Verify(ed25519.PublicKey(b)) == nil {
				trusted = true
				break
			}
		}
		if !trusted {
			fail("Report is not signed by a trusted key")
		}
	}
	return d
}

type Change struct {
	Name   string `json:"name"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type Comparison struct {
	Base             string   `json:"base"`
	Head             string   `json:"head"`
	SameProfile      bool     `json:"same_profile"`
	Changes          []Change `json:"changes"`
	AddedFindings    []string `json:"added_findings"`
	ResolvedFindings []string `json:"resolved_findings"`
}

func Compare(base, head *report.Report) Comparison {
	c := Comparison{Base: base.ID, Head: head.ID, SameProfile: base.ProfileSHA256 == head.ProfileSHA256, Changes: []Change{}, AddedFindings: []string{}, ResolvedFindings: []string{}}
	if base.Status != head.Status {
		c.Changes = append(c.Changes, Change{Name: "readiness", Before: base.Status, After: head.Status})
	}
	before := map[string]string{}
	for _, s := range base.Scenarios {
		before[s.Name] = fmt.Sprint(s.Passed)
	}
	for _, s := range head.Scenarios {
		after := fmt.Sprint(s.Passed)
		old, ok := before[s.Name]
		if !ok {
			old = "untested"
		}
		if old != after {
			c.Changes = append(c.Changes, Change{Name: s.Name, Before: old, After: after})
		}
		delete(before, s.Name)
	}
	for name, old := range before {
		c.Changes = append(c.Changes, Change{Name: name, Before: old, After: "untested"})
	}
	fingerprint := func(f report.Finding) string { return fmt.Sprintf("%s|%s|%s:%d", f.Rule, f.Service, f.Path, f.Line) }
	findings := map[string]bool{}
	for _, f := range base.Findings {
		findings[fingerprint(f)] = true
	}
	afterFindings := map[string]bool{}
	for _, f := range head.Findings {
		k := fingerprint(f)
		if afterFindings[k] {
			continue
		}
		afterFindings[k] = true
		if !findings[k] {
			c.AddedFindings = append(c.AddedFindings, k)
		}
		delete(findings, k)
	}
	for k := range findings {
		c.ResolvedFindings = append(c.ResolvedFindings, k)
	}
	sort.Strings(c.AddedFindings)
	sort.Strings(c.ResolvedFindings)
	sort.Slice(c.Changes, func(i, j int) bool { return c.Changes[i].Name < c.Changes[j].Name })
	return c
}
