package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/kube"
	"github.com/cenab/airgapproof/internal/probe"
	"github.com/cenab/airgapproof/internal/report"
)

type Cluster struct {
	Node                  string
	Lab                   *Lab
	Kubeconfig, Namespace string
}

func Kubernetes(ctx context.Context, c *config.Config, opts Options) (r *report.Report, err error) {
	m, err := kube.Load(c)
	if err != nil {
		return nil, err
	}
	for _, s := range c.Scenarios {
		if s.Type != "exec" && s.Type != "restart" {
			continue
		}
		target := s.Service
		if !strings.Contains(target, "/") {
			target = "deployment/" + target
		}
		found := false
		for _, object := range m.Objects {
			kind := strings.ToLower(fmt.Sprint(object["kind"]))
			name := fmt.Sprint(object["metadata"].(map[string]any)["name"])
			if target == kind+"/"+name {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("scenario %q targets an undeclared workload", s.Name)
		}
	}
	b, _ := json.Marshal(m.List())
	profile, _ := json.Marshal(c)
	r = report.New(c.Application.Name, "developer", "kubernetes", report.Hash(append(profile, b...)))
	r.Revision = opts.Revision
	r.Findings, r.Gaps = scan(c, []string{"Only the declared scenarios and rendered manifests are covered; Helm rendering and external operators must be supplied separately.", "kind's default CNI does not enforce NetworkPolicy; egress isolation is enforced at the node's outer Docker network instead.", "The single-node test cluster is disposable; multi-node scheduling and hardware failover are untested."})
	defer func() {
		if err != nil {
			r.Fail("execution.error", "execution", "", err.Error(), "Check kind, kubectl, Docker, and preloaded images.")
		}
		r.Finish(len(c.Scenarios))
	}()
	if err = checkArtifacts(ctx, c, append(m.Images, c.Application.NodeImage), r); err != nil {
		return r, err
	}
	lab := &Lab{Name: "ap-" + r.ID, Networks: map[string]string{}, Containers: map[string]Container{}, opts: opts}
	lab.Dir, err = os.MkdirTemp("", "airgapproof-k8s-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(lab.Dir)
	cluster := &Cluster{Lab: lab, Kubeconfig: filepath.Join(lab.Dir, "kubeconfig"), Namespace: "airgapproof"}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, e := engine.Run(cleanup, nil, "kind", "delete", "cluster", "--name", lab.Name)
		if e != nil {
			r.Fail("cleanup.cluster", "execution", "", "Disposable cluster cleanup failed.", "Delete kind cluster "+lab.Name)
		}
		if e = lab.cleanup(cleanup); e != nil {
			r.Fail("cleanup.network", "execution", "", "Run-owned network or helpers remain.", "Inspect resources with label airgapproof.run="+lab.Name)
		}
	}()
	network := lab.Name + "-nodes"
	lab.Networks["nodes"] = network
	if _, err = CreateNetwork(ctx, network, lab.Name); err != nil {
		return r, err
	}
	lab.Helper = lab.Name + "-dns"
	if _, err = engine.Docker(ctx, "run", "--detach", "--pull", "never", "--name", lab.Helper, "--label", "airgapproof.run="+lab.Name, "--network", network, "--network-alias", "host.docker.internal", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--read-only", c.Artifacts.HelperImage, "dns"); err != nil {
		return r, err
	}
	dnsCT, e := Inspect(ctx, lab.Helper)
	if e != nil {
		return r, e
	}
	dnsIP := dnsCT.NetworkSettings.Networks[network].IPAddress
	lab.ServiceIPs = map[string]string{dnsIP: "airgapproof-dns"}
	lab.InternalPrefixes = []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("10.96.0.0/16")}
	fmt.Fprintln(opts.Log, "Creating isolated kind cluster", lab.Name)
	kindConfig := []byte("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  apiServerAddress: 127.0.0.1\n  podSubnet: 10.244.0.0/16\n  serviceSubnet: 10.96.0.0/16\nnodes:\n  - role: control-plane\n")
	path := filepath.Join(lab.Dir, "kind.yaml")
	if err = engine.WritePrivate(path, kindConfig); err != nil {
		return r, err
	}
	if _, err = engine.RunEnv(ctx, nil, []string{"KIND_EXPERIMENTAL_DOCKER_NETWORK=" + network}, "kind", "create", "cluster", "--retain", "--name", lab.Name, "--image", c.Application.NodeImage, "--config", path, "--kubeconfig", cluster.Kubeconfig, "--wait", "90s"); err != nil && !strings.Contains(engine.Diagnostic(err), "failed to get api server port") {
		return r, err
	}
	err = nil
	node := lab.Name + "-control-plane"
	cluster.Node = node
	if _, err = cluster.kubectl(ctx, nil, "get", "--raw", "/readyz"); err != nil {
		return r, fmt.Errorf("isolated cluster API is not ready: %w", err)
	}
	ct, e := Inspect(ctx, node)
	if e != nil {
		return r, e
	}
	if len(ct.NetworkSettings.Networks) != 1 {
		return r, fmt.Errorf("kind node has unexpected network attachments")
	}
	ct.Config.Labels["com.docker.compose.service"] = "kind-node"
	lab.Containers[ct.ID] = ct
	routes, e := engine.Docker(ctx, "exec", node, "ip", "route", "show", "default")
	if e != nil || len(bytes.TrimSpace(routes)) > 0 {
		return r, fmt.Errorf("kind node has an external default route")
	}
	// kind's DNS compatibility rules assume a host gateway; point node DNS directly at the sandbox resolver.
	for _, chain := range []string{"DOCKER_OUTPUT", "DOCKER_POSTROUTING"} {
		if _, err = engine.Docker(ctx, "exec", node, "iptables", "-t", "nat", "-F", chain); err != nil {
			return r, err
		}
	}
	if _, err = engine.Run(ctx, strings.NewReader("nameserver "+dnsIP+"\n"), "docker", "exec", "-i", node, "tee", "/etc/resolv.conf"); err != nil {
		return r, err
	}
	corefile := fmt.Sprintf(".:53 {\n errors\n health\n ready\n kubernetes cluster.local in-addr.arpa ip6.arpa { pods insecure fallthrough in-addr.arpa ip6.arpa }\n forward . %s\n cache 5\n reload\n loop\n}\n", dnsIP)
	patch, _ := json.Marshal(map[string]any{"data": map[string]string{"Corefile": corefile}})
	if _, err = cluster.kubectl(ctx, nil, "--namespace", "kube-system", "patch", "configmap", "coredns", "--type", "merge", "--patch", string(patch)); err != nil {
		return r, err
	}
	if _, err = cluster.kubectl(ctx, nil, "--namespace", "kube-system", "rollout", "restart", "deployment/coredns"); err != nil {
		return r, err
	}
	images := append(append([]string{}, m.Images...), c.Artifacts.HelperImage)
	for i, image := range images {
		platform, e := engine.Docker(ctx, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image)
		if e != nil {
			return r, e
		}
		archive := filepath.Join(lab.Dir, fmt.Sprintf("image-%d.tar", i))
		if _, err = engine.Docker(ctx, "image", "save", "--platform", strings.TrimSpace(string(platform)), "--output", archive, image); err != nil {
			return r, err
		}
		_, err = engine.Run(ctx, nil, "kind", "load", "image-archive", "--name", lab.Name, archive)
		_ = os.Remove(archive)
		if err != nil {
			return r, err
		}
	}
	if _, err = cluster.kubectl(ctx, nil, "create", "namespace", cluster.Namespace); err != nil {
		return r, err
	}
	helperPod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]string{"name": "airgapproof-probe", "namespace": cluster.Namespace}, "spec": map[string]any{"automountServiceAccountToken": false, "containers": []any{map[string]any{"name": "probe", "image": c.Artifacts.HelperImage, "imagePullPolicy": "Never", "args": []string{"dns"}, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}, "add": []string{"NET_BIND_SERVICE"}}}}}}}
	b, _ = json.Marshal(helperPod)
	if _, err = cluster.kubectl(ctx, bytes.NewReader(b), "apply", "-f", "-"); err != nil {
		return r, err
	}
	if _, err = cluster.kubectl(ctx, nil, "-n", cluster.Namespace, "wait", "--for=condition=Ready", "pod/airgapproof-probe", "--timeout=60s"); err != nil {
		return r, err
	}
	if _, err = cluster.kubectl(ctx, nil, "-n", cluster.Namespace, "exec", "airgapproof-probe", "--", "/helper", "canary", "egress-only"); err != nil {
		return r, fmt.Errorf("Kubernetes egress canary failed")
	}
	r.Isolation.Verified = true
	r.Isolation.Checks = append(r.Isolation.Checks, "Single kind node is attached only to an internal Docker network with isolated gateway mode.", "Node has no external default route; pod IPv4/IPv6 TCP egress canaries failed.", "CoreDNS forwards external names only to the non-forwarding sandbox resolver.", "Workload images are loaded locally and imagePullPolicy is Never.", "Cluster-scoped resources, external services, host mounts, and elevated application privileges were rejected.")
	if err = lab.startTrace(ctx, c, r); err != nil {
		return r, err
	}
	m.Harden(cluster.Namespace)
	b, _ = json.Marshal(m.List())
	if _, err = cluster.kubectl(ctx, bytes.NewReader(b), "apply", "-f", "-"); err != nil {
		return r, err
	}
	for _, s := range c.Scenarios {
		if err = cluster.collectPods(ctx, nil); err != nil {
			return r, err
		}
		result := cluster.scenario(ctx, c, s)
		r.Scenarios = append(r.Scenarios, result)
		fmt.Fprintf(opts.Log, "  %s: %t\n", s.Name, result.Passed)
	}
	if err = cluster.collectPods(ctx, r); err != nil {
		return r, err
	}
	if err = lab.finishTrace(ctx, c, r); err != nil {
		return r, err
	}
	b, _ = engine.Docker(ctx, "logs", lab.Helper)
	nodeIP := ct.NetworkSettings.Networks[network].IPAddress
	nodeCT := ct
	nodeCT.Config.Labels["com.docker.compose.service"] = "cluster-dns"
	nodeCT.NetworkSettings.Networks = map[string]struct {
		IPAddress string `json:"IPAddress"`
	}{network: {IPAddress: nodeIP}}
	lab.Containers["cluster-dns"] = nodeCT
	lab.readObservations(b, r, true)
	r.Gaps = append(r.Gaps, "Forwarded Kubernetes DNS queries identify the cluster resolver rather than the originating pod process.", "Syscall tracing covers connect/sendto; sendmsg, io_uring, inherited connections, and other protocol paths remain untested.")
	applyAttempts(c, r)
	return r, nil
}
func (c *Cluster) kubectl(ctx context.Context, in *bytes.Reader, args ...string) ([]byte, error) {
	if in == nil {
		return engine.Docker(ctx, append([]string{"exec", c.Node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf"}, args...)...)
	}
	return engine.Run(ctx, in, "docker", append([]string{"exec", "-i", c.Node, "kubectl", "--kubeconfig", "/etc/kubernetes/admin.conf"}, args...)...)
}
func (c *Cluster) scenario(ctx context.Context, profile *config.Config, s config.Scenario) report.Scenario {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.Duration())
	defer cancel()
	r := report.Scenario{Name: s.Name, Type: s.Type}
	switch s.Type {
	case "http":
		b, _ := json.Marshal(s)
		out, err := c.kubectl(ctx, bytes.NewReader(b), "-n", c.Namespace, "exec", "-i", "airgapproof-probe", "--", "/helper", "http")
		var p probe.Result
		if json.Unmarshal(out, &p) == nil {
			r.Passed = p.Passed && err == nil
			r.Detail = fmt.Sprintf("%s; status=%d; body_sha256=%s", p.Detail, p.Status, p.BodySHA256)
		} else {
			r.Detail = "Kubernetes HTTP probe could not execute"
		}
	case "exec":
		resource := s.Service
		if !strings.Contains(resource, "/") {
			resource = "deployment/" + resource
		}
		args := append([]string{"-n", c.Namespace, "exec", resource, "--"}, s.Command...)
		_, err := c.kubectl(ctx, nil, args...)
		code := engine.ExitCode(err)
		r.Passed = code == s.ExpectedExitCode && ctx.Err() == nil
		r.Detail = fmt.Sprintf("Command exit code=%d, expected=%d; output omitted", code, s.ExpectedExitCode)
	case "restart":
		resource := s.Service
		if !strings.Contains(resource, "/") {
			resource = "deployment/" + resource
		}
		if !strings.HasPrefix(resource, "deployment/") && !strings.HasPrefix(resource, "statefulset/") {
			r.Detail = "Restart supports deployment/name or statefulset/name"
			break
		}
		_, err := c.kubectl(ctx, nil, "-n", c.Namespace, "rollout", "restart", resource)
		if err == nil {
			_, err = c.kubectl(ctx, nil, "-n", c.Namespace, "rollout", "status", resource, "--timeout="+s.Timeout)
		}
		if err == nil {
			v := c.scenario(ctx, profile, profile.Scenario(s.Verify))
			r.Passed = v.Passed
			r.Detail = "Rollout recovery: " + v.Detail
		} else {
			r.Detail = "Rollout recovery failed"
		}
	}
	r.DurationMS = time.Since(start).Milliseconds()
	return r
}
func (c *Cluster) collectPods(ctx context.Context, r *report.Report) error {
	b, err := c.kubectl(ctx, nil, "-n", c.Namespace, "get", "pods", "-o", "json")
	if err != nil {
		return err
	}
	var list struct {
		Items []struct {
			Metadata struct{ Name string }
			Status   struct {
				Phase             string
				PodIP             string
				ContainerStatuses []struct {
					Name        string
					Image       string
					ImageID     string
					ContainerID string
					Ready       bool
				}
			}
		}
	}
	if err = json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, pod := range list.Items {
		if pod.Metadata.Name == "airgapproof-probe" {
			continue
		}
		if r != nil && len(pod.Status.ContainerStatuses) == 0 {
			r.Fail("service.unavailable", "functional", pod.Metadata.Name, "Workload has no running containers.", "Check offline image availability and startup dependencies.")
		}
		for _, ct := range pod.Status.ContainerStatuses {
			state := pod.Status.Phase
			if state == "Running" && !ct.Ready {
				state = "NotReady"
			}
			if r != nil {
				r.Services = append(r.Services, report.Service{Name: pod.Metadata.Name + "/" + ct.Name, Image: ct.Image, ImageID: ct.ImageID, State: state})
			}
			if r != nil && state != "Running" && state != "Succeeded" {
				r.Fail("service.unavailable", "functional", pod.Metadata.Name, "Workload is "+state+".", "Package missing artifacts and resolve offline startup dependencies.")
			}
			id := strings.TrimPrefix(ct.ContainerID, "containerd://")
			synthetic := Container{ID: id}
			synthetic.Config.Labels = map[string]string{"com.docker.compose.service": pod.Metadata.Name + "/" + ct.Name}
			synthetic.NetworkSettings.Networks = map[string]struct {
				IPAddress string `json:"IPAddress"`
			}{"pod": {IPAddress: pod.Status.PodIP}}
			c.Lab.Containers[id] = synthetic
		}
	}
	return nil
}
func applyAttempts(c *config.Config, r *report.Report) {
	n := 0
	for _, o := range r.Observations {
		if o.External {
			n++
		}
	}
	if n > 0 {
		severity := "warning"
		if c.Isolation.FailOnAttempts {
			severity = "error"
		}
		r.Findings = append(r.Findings, report.Finding{Rule: "runtime.external-attempt", Severity: severity, Category: "network_attempt", Message: fmt.Sprintf("Observed %d external network attempts.", n), Remediation: "Disable optional egress or provide offline services; use scenario outcomes to assess operational dependence."})
	}
}
