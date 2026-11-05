package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/bundle"
	"github.com/cenab/airgapproof/internal/compose"
	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/discovery"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/probe"
	"github.com/cenab/airgapproof/internal/report"
)

type Options struct {
	Log      io.Writer
	Timeout  time.Duration
	Revision string
}
type Container struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
		Health   *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}
type Lab struct {
	InternalPrefixes          []netip.Prefix
	ServiceIPs                map[string]string
	Name, Dir, Helper, Tracer string
	Networks                  map[string]string
	Containers                map[string]Container
	configPath                string
	opts                      Options
}

func Test(ctx context.Context, c *config.Config, opts Options) (r *report.Report, err error) {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if c.Isolation.Mode == "disconnected" {
		return VMTest(ctx, c, opts)
	}
	if len(c.Application.Kubernetes) > 0 {
		return Kubernetes(ctx, c, opts)
	}
	p, err := compose.Load(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, s := range c.Scenarios {
		if (s.Type == "exec" || s.Type == "restart") && p.Services[s.Service] == nil {
			return nil, fmt.Errorf("scenario %q targets unknown service %q", s.Name, s.Service)
		}
	}
	profile, _ := json.Marshal(c)
	r = report.New(c.Application.Name, c.Isolation.Mode, "compose", report.Hash(append(profile, []byte(p.Hash)...)))
	r.Revision = opts.Revision
	r.Gaps = append(r.Gaps, "Only declared functional scenarios are covered; unexercised application paths remain untested.", "Developer mode shares the Docker host kernel; it is not a hostile-workload security boundary.")
	r.Findings, r.Gaps = scan(c, r.Gaps)
	defer func() {
		if err != nil {
			r.Fail("execution.error", "execution", "", err.Error(), "Check local tooling, the supported deployment profile, and preloaded artifacts.")
		}
		r.Finish(len(c.Scenarios))
	}()
	if err = checkArtifacts(ctx, c, p.Images(), r); err != nil {
		return r, err
	}
	lab := &Lab{Name: "ap-" + r.ID, Networks: map[string]string{}, Containers: map[string]Container{}, opts: opts}
	lab.Dir, err = os.MkdirTemp("", "airgapproof-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(lab.Dir)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if e := lab.cleanup(cleanup); e != nil {
			r.Fail("cleanup.failed", "execution", "", "Some run-owned resources could not be removed.", "Remove only Docker resources with label airgapproof.run="+lab.Name)
		}
	}()
	fmt.Fprintln(opts.Log, "Creating isolated Compose project", lab.Name)
	names := []string{}
	for name := range p.Networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, key := range names {
		name := lab.Name + "_" + key
		if _, err = CreateNetwork(ctx, name, lab.Name); err != nil {
			return r, err
		}
		lab.Networks[key] = name
	}
	if len(names) == 0 {
		return r, fmt.Errorf("no supported application networks")
	}
	lab.Helper = lab.Name + "-probe"
	if _, err = engine.Docker(ctx, "create", "--name", lab.Helper, "--label", "airgapproof.run="+lab.Name, "--network", lab.Networks[names[0]], "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--read-only", "--security-opt", "no-new-privileges:true", c.Artifacts.HelperImage, "dns"); err != nil {
		return r, err
	}
	for _, key := range names[1:] {
		if _, err = engine.Docker(ctx, "network", "connect", lab.Networks[key], lab.Helper); err != nil {
			return r, err
		}
	}
	if _, err = engine.Docker(ctx, "start", lab.Helper); err != nil {
		return r, err
	}
	var helper Container
	if helper, err = Inspect(ctx, lab.Helper); err != nil {
		return r, err
	}
	dns := []string{}
	for _, key := range names {
		dns = append(dns, helper.NetworkSettings.Networks[lab.Networks[key]].IPAddress)
	}
	p.Harden(lab.Name, lab.Networks, dns)
	if err = lab.assignAddresses(ctx, p); err != nil {
		return r, err
	}
	b, err := json.Marshal(p.Model)
	if err != nil {
		return r, err
	}
	lab.configPath = filepath.Join(lab.Dir, "compose.json")
	if err = engine.WritePrivate(lab.configPath, b); err != nil {
		return r, err
	}
	if _, err = lab.compose(ctx, "create", "--pull", "never", "--no-build"); err != nil {
		return r, err
	}
	if err = lab.refresh(ctx); err != nil {
		return r, err
	}
	if _, err = engine.Docker(ctx, "exec", lab.Helper, "/helper", "canary"); err != nil {
		return r, fmt.Errorf("sandbox routing or external-connectivity check failed: %w", err)
	}
	r.Isolation.Verified = true
	r.Isolation.Checks = append(r.Isolation.Checks, "Every application network is internal with isolated gateway mode and IPv6 disabled.", "Probe has no IPv4/IPv6 default route and external TCP canaries failed.", "External DNS is directed to a resolver that returns NXDOMAIN without forwarding.", "Application privilege, mount, namespace, image, and network settings passed preflight validation.", "Builds and image pulls are disabled; all images were inspected locally before startup.", "Published host ports are omitted in the test copy; private service topology is preserved.")
	if err = lab.startTrace(ctx, c, r); err != nil {
		return r, err
	}
	fmt.Fprintln(opts.Log, "Starting preloaded services and running functional scenarios")
	if _, startErr := lab.compose(ctx, "start"); startErr != nil {
		r.Fail("startup.failed", "functional", "", "One or more services failed to start.", "Inspect missing offline artifacts and startup dependencies.")
	}
	for _, s := range c.Scenarios {
		r.Scenarios = append(r.Scenarios, lab.scenario(ctx, c, s))
		fmt.Fprintf(opts.Log, "  %s: %t\n", s.Name, r.Scenarios[len(r.Scenarios)-1].Passed)
	}
	if err = lab.refresh(ctx); err != nil {
		return r, err
	}
	for _, name := range p.Names() {
		state := "missing"
		imageID := ""
		code := 0
		for _, ct := range lab.Containers {
			if ct.Config.Labels["com.docker.compose.service"] == name {
				state = ct.State.Status
				code = ct.State.ExitCode
				imageID = ct.Image
				if ct.State.Health != nil && ct.State.Health.Status == "unhealthy" {
					state = "unhealthy"
				}
			}
		}
		r.Services = append(r.Services, report.Service{Name: name, Image: p.Services[name].(map[string]any)["image"].(string), ImageID: imageID, State: state, ExitCode: code})
		if state != "running" && (state != "exited" || code != 0) {
			r.Fail("service.unavailable", "functional", name, "Service is "+state+".", "Package required artifacts and remove mandatory internet calls from startup.")
		}
	}
	if err = lab.collect(ctx, c, r); err != nil {
		return r, err
	}
	return r, nil
}
func (l *Lab) assignAddresses(ctx context.Context, p *compose.Project) error {
	l.ServiceIPs = map[string]string{}
	for key, network := range l.Networks {
		b, err := engine.Docker(ctx, "network", "inspect", network)
		if err != nil {
			return err
		}
		var inspected []struct {
			IPAM struct{ Config []struct{ Subnet string } }
		}
		if err = json.Unmarshal(b, &inspected); err != nil || len(inspected) != 1 || len(inspected[0].IPAM.Config) != 1 {
			return fmt.Errorf("unsupported network address pool")
		}
		prefix, err := netip.ParsePrefix(inspected[0].IPAM.Config[0].Subnet)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("unsupported network address family")
		}
		addr := prefix.Addr()
		for i := 0; i < 10; i++ {
			addr = addr.Next()
		}
		for _, name := range p.Names() {
			s := p.Services[name].(map[string]any)
			networks, _ := s["networks"].(map[string]any)
			n, ok := networks[key]
			if !ok {
				continue
			}
			if !prefix.Contains(addr) {
				return fmt.Errorf("network address pool is too small")
			}
			m, _ := n.(map[string]any)
			if m == nil {
				m = map[string]any{}
				networks[key] = m
			}
			m["ipv4_address"] = addr.String()
			l.ServiceIPs[addr.String()] = name
			addr = addr.Next()
		}
	}
	return nil
}
func scan(c *config.Config, gaps []string) ([]report.Finding, []string) {
	f, g := discovery.Scan(c.BaseDir)
	return f, append(gaps, g...)
}
func checkArtifacts(ctx context.Context, c *config.Config, images []string, r *report.Report) error {
	missing := false
	seen := map[string]bool{}
	for _, image := range append(images, c.Artifacts.HelperImage) {
		if seen[image] {
			continue
		}
		seen[image] = true
		b, err := engine.Docker(ctx, "image", "inspect", "--format", "{{.Id}}", image)
		if err == nil && strings.HasPrefix(image, bundle.ImagePrefix) && strings.TrimSpace(string(b)) != "sha256:"+strings.TrimPrefix(image, bundle.ImagePrefix) {
			err = fmt.Errorf("bundle image alias no longer matches its content identity")
		}
		r.Artifacts = append(r.Artifacts, report.Artifact{Path: "image:" + image, SHA256: strings.TrimSpace(string(b)), Present: err == nil})
		if err != nil {
			missing = true
			r.Fail("artifact.missing-image", "completeness", "", "Image is not preloaded: "+image, "Run airgapproof prepare while online, or load a verified artifact bundle before testing.")
		}
	}
	for _, path := range c.Artifacts.Files {
		hash, _, err := bundle.HashFile(c.Path(path))
		a := report.Artifact{Path: path, Present: err == nil}
		if err == nil {
			a.SHA256 = hash
		} else {
			missing = true
			r.Fail("artifact.missing-file", "completeness", "", "Required artifact is absent: "+path, "Include the artifact in the offline bundle.")
		}
		r.Artifacts = append(r.Artifacts, a)
	}
	if missing {
		return fmt.Errorf("offline artifacts are incomplete")
	}
	return nil
}
func CreateNetwork(ctx context.Context, name, run string) (string, error) {
	if _, err := engine.Docker(ctx, "network", "create", "--label", "airgapproof.run="+run, "--internal", "--driver", "bridge", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", name); err != nil {
		return "", fmt.Errorf("create isolated network (Docker Engine 28+ required): %w", err)
	}
	b, err := engine.Docker(ctx, "network", "inspect", name)
	if err != nil {
		return "", err
	}
	var n []struct {
		Internal   bool
		EnableIPv6 bool
		Options    map[string]string
	}
	if err = json.Unmarshal(b, &n); err != nil {
		return "", err
	}
	if len(n) != 1 || !n[0].Internal || n[0].EnableIPv6 || n[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" {
		return "", fmt.Errorf("network isolation verification failed")
	}
	return name, nil
}
func Inspect(ctx context.Context, id string) (Container, error) {
	b, err := engine.Docker(ctx, "inspect", id)
	if err != nil {
		return Container{}, err
	}
	var c []Container
	err = json.Unmarshal(b, &c)
	if err != nil || len(c) != 1 {
		return Container{}, fmt.Errorf("invalid container inspection")
	}
	return c[0], nil
}
func (l *Lab) compose(ctx context.Context, args ...string) ([]byte, error) {
	return engine.Docker(ctx, append([]string{"compose", "--project-name", l.Name, "--file", l.configPath}, args...)...)
}
func (l *Lab) refresh(ctx context.Context) error {
	b, err := l.compose(ctx, "ps", "--all", "--quiet")
	if err != nil {
		return err
	}
	for _, id := range engine.Lines(b) {
		c, err := Inspect(ctx, id)
		if err != nil {
			return err
		}
		l.Containers[id] = c
	}
	return nil
}
func (l *Lab) scenario(ctx context.Context, c *config.Config, s config.Scenario) report.Scenario {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.Duration())
	defer cancel()
	result := report.Scenario{Name: s.Name, Type: s.Type}
	switch s.Type {
	case "http":
		b, _ := json.Marshal(s)
		out, err := engine.Run(ctx, bytes.NewReader(b), "docker", "exec", "-i", l.Helper, "/helper", "http")
		var p probe.Result
		if json.Unmarshal(out, &p) == nil {
			result.Passed = p.Passed
			result.Detail = fmt.Sprintf("%s; status=%d; body_sha256=%s", p.Detail, p.Status, p.BodySHA256)
		} else {
			result.Detail = "Probe could not execute"
		}
		if ctx.Err() != nil || err != nil {
			result.Passed = false
		}
	case "exec":
		args := append([]string{"exec", "--no-TTY", s.Service}, s.Command...)
		_, err := l.compose(ctx, args...)
		code := engine.ExitCode(err)
		result.Passed = code == s.ExpectedExitCode && ctx.Err() == nil
		result.Detail = fmt.Sprintf("Command exit code=%d, expected=%d; output omitted", code, s.ExpectedExitCode)
	case "restart":
		_, err := l.compose(ctx, "restart", s.Service)
		if err != nil {
			result.Detail = "Service restart failed"
		} else {
			verify := l.scenario(ctx, c, c.Scenario(s.Verify))
			result.Passed = verify.Passed
			result.Detail = "Restart followed by " + s.Verify + ": " + verify.Detail
		}
	}
	result.DurationMS = time.Since(start).Milliseconds()
	return result
}
func (l *Lab) cleanup(ctx context.Context) error {
	var first error
	if l.configPath != "" {
		if _, err := l.compose(ctx, "down", "--volumes", "--remove-orphans", "--timeout", "2"); err != nil {
			first = err
		}
	}
	for _, id := range []string{l.Tracer, l.Helper} {
		if id != "" {
			if _, err := engine.Docker(ctx, "rm", "--force", id); err != nil && first == nil {
				first = err
			}
		}
	}
	for _, name := range l.Networks {
		if _, err := engine.Docker(ctx, "network", "rm", name); err != nil && first == nil {
			first = err
		}
	}
	return first
}
