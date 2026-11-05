package run

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/engine"
)

func TestComposeAIIntegration(t *testing.T) {
	if os.Getenv("AIRGAPPROOF_INTEGRATION") != "1" {
		t.Skip("set AIRGAPPROOF_INTEGRATION=1 after make demo-prepare")
	}
	path := filepath.Join("..", "..", "examples", "ai-app", "airgapproof.yaml")
	c, err := config.Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AIRGAPPROOF_REQUIRE_TRACING") == "1" {
		c.Isolation.Tracing = "required"
	}
	c.Scenarios = append(c.Scenarios, config.Scenario{Name: "blocked-raw-ip", Type: "exec", Service: "api", Command: []string{"python", "-c", "import socket; s=socket.socket(); s.settimeout(1); assert s.connect_ex(('1.1.1.1',443)) != 0"}, Timeout: "5s"})
	r, err := Test(context.Background(), c, Options{Log: os.Stderr, Timeout: 2 * time.Minute})
	if err != nil || r.Status != "ready" {
		t.Fatalf("self-contained application failed: %v %+v", err, r)
	}
	if r.Isolation.Tracing {
		found := false
		for _, o := range r.Observations {
			if o.Destination == "1.1.1.1" && o.External && o.PID > 0 && o.Service == "api" && o.Result < 0 {
				found = true
			}
		}
		if !found {
			t.Fatal("failed raw-IP connection lacks process-attributed evidence")
		}
	}
	c, err = config.Load(path, filepath.Join("..", "..", "examples", "ai-app", "compose.remote.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c.Scenarios[0].Timeout = "10s"
	c.Scenarios[3].Timeout = "10s"
	r, err = Test(context.Background(), c, Options{Log: os.Stderr, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "not_ready" || r.Scenarios[0].Passed || r.Scenarios[1].Passed {
		t.Fatal("remote model unexpectedly works offline")
	}
	for _, o := range r.Observations {
		if o.Kind == "dns" && o.Destination == "huggingface.co." && o.Service != "inference" {
			t.Fatalf("query attributed to wrong service after restart: %+v", o)
		}
	}
	b, err := engine.Docker(context.Background(), "ps", "--all", "--quiet", "--filter", "label=airgapproof.run=ap-"+r.ID)
	if err != nil || len(engine.Lines(b)) > 0 {
		t.Fatal("application resources leaked", err, string(b))
	}
}
