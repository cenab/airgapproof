package run

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/report"
)

func (l *Lab) startTrace(ctx context.Context, c *config.Config, r *report.Report) error {
	if c.Isolation.Tracing == "off" {
		r.Gaps = append(r.Gaps, "Process-level connection tracing was disabled; only resolver queries are observed.")
		return nil
	}
	l.Tracer = l.Name + "-trace"
	targets := []string{}
	for id := range l.Containers {
		targets = append(targets, id)
	}
	b, _ := json.Marshal(targets)
	_, err := engine.Docker(ctx, "run", "--detach", "--pull", "never", "--name", l.Tracer, "--label", "airgapproof.run="+l.Name, "--network", "none", "--pid", "host", "--privileged", "--read-only", "--volume", "/proc:/host/proc:ro", "--volume", "/sys:/sys:ro", "--env", "AIRGAPPROOF_TARGETS="+string(b), c.Artifacts.HelperImage, "trace")
	if err == nil {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			b, _ := engine.Docker(ctx, "logs", l.Tracer)
			if bytes.Contains(b, []byte(`"kind":"ready"`)) {
				r.Isolation.Tracing = true
				r.Isolation.Checks = append(r.Isolation.Checks, "Linux eBPF connect/sendto tracing attached before application startup.")
				return nil
			}
			ct, e := Inspect(ctx, l.Tracer)
			if e != nil || !ct.State.Running {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	} else {
		l.Tracer = ""
	}
	if c.Isolation.Tracing == "required" {
		return fmt.Errorf("required eBPF tracing could not attach; use a supported Linux kernel with tracefs and BPF privileges")
	}
	r.Gaps = append(r.Gaps, "eBPF tracing unavailable: raw-IP attempts, non-resolver DNS, and process attribution are not covered.")
	return nil
}
func (l *Lab) collect(ctx context.Context, c *config.Config, r *report.Report) error {
	if ct, err := Inspect(ctx, l.Helper); err == nil {
		ct.Config.Labels["com.docker.compose.service"] = "airgapproof-probe"
		l.Containers[ct.ID] = ct
	}
	if err := l.finishTrace(ctx, c, r); err != nil {
		return err
	}
	b, err := engine.Docker(ctx, "logs", l.Helper)
	if err != nil {
		return err
	}
	l.readObservations(b, r, true)
	external := 0
	for _, o := range r.Observations {
		if o.External {
			external++
		}
	}
	if external > 0 {
		severity := "warning"
		if c.Isolation.FailOnAttempts {
			severity = "error"
		}
		r.Findings = append(r.Findings, report.Finding{Rule: "runtime.external-attempt", Severity: severity, Category: "network_attempt", Message: fmt.Sprintf("Observed %d external network attempts during the tested workflows.", external), Remediation: "Disable optional outbound features or provide local services. Scenario results establish whether the tested operations still work."})
	}
	r.Gaps = append(r.Gaps, "Tracing covers connect and sendto syscalls, not sendmsg, io_uring, inherited connections, or every possible protocol.", "DNS observations identify the source container where possible; they do not provide a process ID.")
	return nil
}
func (l *Lab) finishTrace(ctx context.Context, c *config.Config, r *report.Report) error {
	if l.Tracer == "" {
		return nil
	}
	ct, err := Inspect(ctx, l.Tracer)
	if r.Isolation.Tracing && (err != nil || !ct.State.Running) {
		r.Isolation.Tracing = false
		if c.Isolation.Tracing == "required" {
			return fmt.Errorf("required runtime tracer stopped before test completion")
		}
		r.Gaps = append(r.Gaps, "Runtime tracer stopped before all workflows completed.")
	}
	_, _ = engine.Docker(ctx, "stop", "--timeout", "3", l.Tracer)
	b, err := engine.Docker(ctx, "logs", l.Tracer)
	if err != nil && c.Isolation.Tracing == "required" {
		return err
	}
	l.readObservations(b, r, false)
	return nil
}
func (l *Lab) readObservations(b []byte, r *report.Report, dns bool) {
	byIP := map[string]string{}
	for ip, name := range l.ServiceIPs {
		byIP[ip] = name
	}
	byID := map[string]string{}
	for id, ct := range l.Containers {
		name := ct.Config.Labels["com.docker.compose.service"]
		byID[id] = name
		for _, n := range ct.NetworkSettings.Networks {
			byIP[n.IPAddress] = name
		}
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		var raw struct {
			Kind   string `json:"kind"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(s.Bytes(), &raw) != nil {
			continue
		}
		if raw.Kind == "gap" {
			r.Gaps = append(r.Gaps, raw.Detail)
			continue
		}
		if raw.Kind == "ready" {
			continue
		}
		var o report.Observation
		if json.Unmarshal(s.Bytes(), &o) != nil {
			continue
		}
		if dns {
			o.Service = byIP[o.Source]
			if o.Service == "" {
				o.Service = "unattributed"
				r.Gaps = append(r.Gaps, "A DNS query source could not be mapped to an application service.")
			}
		} else {
			o.Service = byID[o.Container]
			if o.Service == "" {
				o.Service = "unattributed-container"
			}
			addresses := map[string]bool{}
			for ip := range byIP {
				addresses[ip] = true
			}
			o.External = !InternalDestination(o.Destination, addresses, l.InternalPrefixes)
		}
		if len(r.Observations) < 30000 {
			r.Observations = append(r.Observations, o)
		}
	}
	if s.Err() != nil {
		r.Gaps = append(r.Gaps, "Some runtime observations could not be parsed.")
	}
}
func InternalDestination(destination string, addresses map[string]bool, prefixes []netip.Prefix) bool {
	ip := net.ParseIP(strings.TrimSuffix(destination, "."))
	addr, err := netip.ParseAddr(destination)
	if err == nil {
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return addresses[destination] || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified()))
}
