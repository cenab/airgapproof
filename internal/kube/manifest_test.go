package kube

import (
	"testing"
)

func pod() map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "api"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "demo:local"}}}}
}
func TestRejectHostEscapeAndControllers(t *testing.T) {
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		o := pod()
		o["spec"].(map[string]any)[key] = true
		if (&Manifest{Objects: []map[string]any{o}}).Validate() == nil {
			t.Fatal(key)
		}
	}
	o := pod()
	o["kind"] = "MutatingWebhookConfiguration"
	if (&Manifest{Objects: []map[string]any{o}}).Validate() == nil {
		t.Fatal("webhook accepted")
	}
	o = pod()
	o["spec"].(map[string]any)["volumes"] = []any{map[string]any{"name": "engine", "hostPath": map[string]any{"path": "/var/run/docker.sock"}}}
	if (&Manifest{Objects: []map[string]any{o}}).Validate() == nil {
		t.Fatal("hostPath accepted")
	}
}
func TestHardensWorkload(t *testing.T) {
	m := &Manifest{Objects: []map[string]any{pod()}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Harden("airgapproof")
	spec := PodSpec(m.Objects[0])
	ct := spec["containers"].([]any)[0].(map[string]any)
	if spec["automountServiceAccountToken"] != false || ct["imagePullPolicy"] != "Never" || ct["securityContext"].(map[string]any)["allowPrivilegeEscalation"] != false {
		t.Fatal("workload not hardened")
	}
}
func TestMalformedContainersFailWithoutPanic(t *testing.T) {
	for _, value := range []any{[]any{"invalid"}, "invalid", []any{map[string]any{"image": "demo:local", "ports": []any{3}}}} {
		o := pod()
		o["spec"].(map[string]any)["containers"] = value
		if (&Manifest{Objects: []map[string]any{o}}).Validate() == nil {
			t.Fatal("invalid container accepted")
		}
	}
}
