package compose

import (
	"context"
	"github.com/cenab/airgapproof/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, s string) (*Project, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(context.Background(), &config.Config{BaseDir: dir, Application: config.Application{Compose: "compose.yaml"}})
}
func TestRejectEscapeSettings(t *testing.T) {
	for _, setting := range []string{"network_mode: host", "privileged: true", "cap_add: [NET_ADMIN]", "pid: host", "devices: [/dev/net/tun]", "extra_hosts: [host.docker.internal:host-gateway]", "use_api_socket: true", "post_start: [{command: touch /tmp/hook}]", "security_opt: [seccomp:unconfined]", "volumes: [/var/run/docker.sock:/var/run/docker.sock:ro]", "logging: {driver: syslog}"} {
		t.Run(strings.Split(setting, ":")[0], func(t *testing.T) {
			_, err := loadFixture(t, "services:\n  api:\n    image: demo:local\n    "+setting+"\n")
			if err == nil {
				t.Fatal("escape setting accepted")
			}
		})
	}
}
func TestRejectExternalResources(t *testing.T) {
	for _, s := range []string{"services: {api: {image: demo:local}}\nnetworks: {default: {external: true}}", "services: {api: {image: demo:local, volumes: [data:/data]}}\nvolumes: {data: {external: true}}", "include: [https://example.invalid/compose.yaml]\nservices: {api: {image: demo:local}}"} {
		if _, err := loadFixture(t, s); err == nil {
			t.Fatal("external resource accepted")
		}
	}
}
func TestHardenPreservesTopologyAndOwnsVolumes(t *testing.T) {
	p, err := loadFixture(t, "services:\n  api:\n    image: demo:local\n    ports: ['8080:80']\n    container_name: production\n    volumes: [data:/data]\n    networks: [front, back]\n  db:\n    image: db:local\n    networks: [back]\nnetworks: {front: {}, back: {}}\nvolumes: {data: {name: production-data}}\n")
	if err != nil {
		t.Fatal(err)
	}
	p.Harden("ap-test", map[string]string{"front": "ap-front", "back": "ap-back"}, []string{"10.0.0.2"})
	api := p.Services["api"].(map[string]any)
	db := p.Services["db"].(map[string]any)
	if api["ports"] != nil || api["container_name"] != nil || api["pull_policy"] != "never" {
		t.Fatal("unsafe defaults retained")
	}
	if len(api["networks"].(map[string]any)) != 2 || len(db["networks"].(map[string]any)) != 1 {
		t.Fatal("topology changed")
	}
	vol := p.Model["volumes"].(map[string]any)["data"].(map[string]any)
	if vol["name"] != "ap-test_data" {
		t.Fatal("production volume reused")
	}
}
