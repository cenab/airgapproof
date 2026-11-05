package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/cenab/airgapproof/internal/engine"
)

type Report struct {
	Version       int           `json:"version"`
	ID            string        `json:"id"`
	CreatedAt     time.Time     `json:"created_at"`
	Application   string        `json:"application"`
	Revision      string        `json:"revision,omitempty"`
	ProfileSHA256 string        `json:"profile_sha256"`
	Status        string        `json:"status"`
	Isolation     Isolation     `json:"isolation"`
	Services      []Service     `json:"services"`
	Artifacts     []Artifact    `json:"artifacts"`
	Scenarios     []Scenario    `json:"scenarios"`
	Findings      []Finding     `json:"findings"`
	Observations  []Observation `json:"observations"`
	Gaps          []string      `json:"gaps"`
	Signature     *Signature    `json:"signature,omitempty"`
}
type Isolation struct {
	Mode     string   `json:"mode"`
	Backend  string   `json:"backend"`
	Verified bool     `json:"verified"`
	Tracing  bool     `json:"tracing"`
	Checks   []string `json:"checks"`
}
type Service struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	ImageID  string `json:"image_id,omitempty"`
	State    string `json:"state"`
	ExitCode int    `json:"exit_code"`
}
type Artifact struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256,omitempty"`
	Present bool   `json:"present"`
}
type Scenario struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Passed     bool   `json:"passed"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail"`
}
type Finding struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Service     string `json:"service,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
	Path        string `json:"path,omitempty"`
	Line        int    `json:"line,omitempty"`
}
type Observation struct {
	Kind        string    `json:"kind"`
	Time        time.Time `json:"time"`
	Service     string    `json:"service,omitempty"`
	Container   string    `json:"container,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	Process     string    `json:"process,omitempty"`
	Source      string    `json:"source,omitempty"`
	Destination string    `json:"destination"`
	Port        uint16    `json:"port,omitempty"`
	Result      int64     `json:"result,omitempty"`
	External    bool      `json:"external"`
	Evidence    string    `json:"evidence"`
}
type Signature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Value     string `json:"value"`
}

func New(name, mode, backend, hash string) *Report {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	return &Report{Version: 1, ID: hex.EncodeToString(id), CreatedAt: time.Now().UTC(), Application: name, ProfileSHA256: hash, Status: "error", Isolation: Isolation{Mode: mode, Backend: backend}, Services: []Service{}, Artifacts: []Artifact{}, Scenarios: []Scenario{}, Findings: []Finding{}, Observations: []Observation{}, Gaps: []string{}}
}
func Hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func (r *Report) Fail(rule, category, service, message, remediation string) {
	r.Findings = append(r.Findings, Finding{Rule: rule, Severity: "error", Category: category, Service: service, Message: message, Remediation: remediation})
}
func (r *Report) Finish(expected int) {
	r.Status = "ready"
	if !r.Isolation.Verified || len(r.Scenarios) != expected {
		r.Status = "not_ready"
	}
	for _, s := range r.Scenarios {
		if !s.Passed {
			r.Status = "not_ready"
		}
	}
	for _, f := range r.Findings {
		if f.Severity == "error" {
			r.Status = "not_ready"
		}
	}
}
func (r *Report) Sign(key ed25519.PrivateKey) error {
	r.Signature = nil
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	r.Signature = &Signature{Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}
	return nil
}
func (r *Report) Verify(trusted ed25519.PublicKey) error {
	if r.Signature == nil || r.Signature.Algorithm != "Ed25519" {
		return errors.New("report has no supported signature")
	}
	s := r.Signature
	pk, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	if len(trusted) > 0 && !ed25519.PublicKey(pk).Equal(trusted) {
		return errors.New("report signer is not trusted")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	copy := *r
	copy.Signature = nil
	b, err := json.Marshal(&copy)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pk, b, sig) {
		return errors.New("report signature does not match its contents")
	}
	return nil
}
func (r *Report) Validate() error {
	if r.Version != 1 || len(r.ID) != 24 || r.Application == "" || len(r.ProfileSHA256) != 64 || r.CreatedAt.IsZero() {
		return errors.New("invalid report identity or version")
	}
	if _, err := hex.DecodeString(r.ID); err != nil {
		return errors.New("invalid report ID")
	}
	if _, err := hex.DecodeString(r.ProfileSHA256); err != nil {
		return errors.New("invalid profile digest")
	}
	if r.Status != "ready" && r.Status != "not_ready" && r.Status != "error" {
		return errors.New("invalid report status")
	}
	if r.Status == "ready" {
		copy := *r
		copy.Finish(len(r.Scenarios))
		if len(r.Scenarios) == 0 || copy.Status != "ready" {
			return errors.New("ready report has failed checks or no workflows")
		}
	}
	return nil
}
func Read(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err = json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, r.Validate()
}
func (r *Report) Write(dir string, formats []string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, format := range formats {
		var b []byte
		var err error
		switch format {
		case "json":
			b, err = json.MarshalIndent(r, "", "  ")
		case "sarif":
			b, err = json.MarshalIndent(r.SARIF(), "", "  ")
		case "html":
			b, err = r.HTML()
		default:
			return fmt.Errorf("unknown format %q", format)
		}
		if err != nil {
			return err
		}
		name := "report." + format
		if format == "sarif" {
			name = "report.sarif"
		}
		if err := engine.WritePrivate(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	return nil
}
func (r *Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	err := htmlReport.Execute(&b, r)
	return b.Bytes(), err
}
func (r *Report) SARIF() map[string]any {
	results := []any{}
	rules := []any{}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			rules = append(rules, map[string]any{"id": f.Rule, "shortDescription": map[string]string{"text": f.Rule}})
			seen[f.Rule] = true
		}
		level := f.Severity
		if level == "info" {
			level = "note"
		}
		result := map[string]any{"ruleId": f.Rule, "level": level, "message": map[string]string{"text": f.Message + " Suggested fix: " + f.Remediation}}
		if f.Path != "" {
			loc := map[string]any{"artifactLocation": map[string]string{"uri": filepath.ToSlash(f.Path)}}
			if f.Line > 0 {
				loc["region"] = map[string]int{"startLine": f.Line}
			}
			result["locations"] = []any{map[string]any{"physicalLocation": loc}}
		}
		results = append(results, result)
	}
	return map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "AirgapProof", "informationUri": "https://github.com/cenab/airgapproof", "rules": rules}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": r.Status != "error"}}}}}
}

var htmlReport = template.Must(template.New("report").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AirgapProof · {{.Application}}</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:1050px;margin:3rem auto;padding:0 1.5rem;color:#162b36;background:#f5f7f8}h1{font-size:2.5rem}h2{margin-top:2rem}table{width:100%;border-collapse:collapse;background:white}th,td{text-align:left;padding:.7rem;border-bottom:1px solid #d4dde2;vertical-align:top}code{overflow-wrap:anywhere}.status{font-weight:bold;font-size:1.5rem}small{color:#425a68}.error{border-left:4px solid #a72525}.warning{border-left:4px solid #946700}article{padding:1rem;margin:1rem 0;background:white}a{color:#075c73}</style><header><p>AIRGAPPROOF / OFFLINE READINESS</p><h1>{{.Application}}</h1><p class="status">{{.Status}}</p><small>Run {{.ID}} · {{.CreatedAt}} · {{.Isolation.Backend}} / {{.Isolation.Mode}}</small></header><main><h2>Functional scenarios</h2><table><tr><th scope="col">Scenario</th><th scope="col">Passed</th><th scope="col">Evidence</th></tr>{{range .Scenarios}}<tr><td>{{.Name}}</td><td>{{.Passed}}</td><td>{{.Detail}} ({{.DurationMS}} ms)</td></tr>{{end}}</table><h2>Services</h2><table><tr><th scope="col">Service</th><th scope="col">Image</th><th scope="col">State</th></tr>{{range .Services}}<tr><td>{{.Name}}</td><td><code>{{.Image}}</code></td><td>{{.State}}</td></tr>{{end}}</table><h2>Findings</h2>{{range .Findings}}<article class="{{.Severity}}"><strong>{{.Severity}} · {{.Rule}}</strong><p>{{.Message}}</p><p>Suggested fix: {{.Remediation}}</p>{{if .Service}}<small>Service: {{.Service}}</small>{{end}}{{if .Path}}<small> · {{.Path}}:{{.Line}}</small>{{end}}</article>{{else}}<p>No findings in the tested profile.</p>{{end}}<h2>Observed network attempts</h2><table><tr><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Evidence</th></tr>{{range .Observations}}<tr><td>{{.Service}} {{.Process}} {{if .PID}}(PID {{.PID}}){{end}}</td><td><code>{{.Destination}}:{{.Port}}</code></td><td>{{.Evidence}}</td></tr>{{end}}</table><h2>Isolation evidence</h2><p>Verified: {{.Isolation.Verified}}</p><ul>{{range .Isolation.Checks}}<li>{{.}}</li>{{end}}</ul><h2>Coverage and limits</h2><p>A pass applies only to this version and the workflows above. It does not prove all possible application behavior works offline.</p><ul>{{range .Gaps}}<li>{{.}}</li>{{end}}</ul><p>Profile SHA-256: <code>{{.ProfileSHA256}}</code></p>{{if .Signature}}<p>Signed with Ed25519. Verify the JSON report against a trusted public key.</p>{{end}}</main></html>`))
