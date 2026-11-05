package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenab/airgapproof/internal/engine"
)

func TestPostgresDashboardIntegration(t *testing.T) {
	if os.Getenv("AIRGAPPROOF_INTEGRATION") != "1" {
		t.Skip("set AIRGAPPROOF_INTEGRATION=1 with Docker and postgres:16-alpine preloaded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	name := "ap-dashboard-test-" + Token()[:12]
	password := Token()
	if _, err := engine.Docker(ctx, "run", "--detach", "--pull", "never", "--name", name, "--label", "airgapproof.test=true", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD="+password, "--tmpfs", "/var/lib/postgresql/data", "postgres:16-alpine"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = engine.Docker(cleanup, "rm", "--force", name)
	})
	port, err := engine.Docker(ctx, "port", name, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	database := fmt.Sprintf("postgresql://postgres:%s@%s/postgres?sslmode=disable", password, strings.TrimSpace(string(port)))
	var store *Store
	for i := 0; i < 50; i++ {
		store, err = Open(ctx, database)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	alpha, aToken, err := store.CreateTeam(ctx, "alpha", Policy{MinScenarios: 1})
	if err != nil {
		t.Fatal(err)
	}
	beta, bToken, err := store.CreateTeam(ctx, "beta", Policy{})
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(store, Token(), "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	request := func(method, path, token string, body []byte) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	r := evidence()
	b, _ := json.Marshal(r)
	status, out := request("POST", "/api/runs", aToken, b)
	if status != 201 {
		t.Fatalf("upload: %d %s", status, out)
	}
	var saved Run
	_ = json.Unmarshal(out, &saved)
	if !saved.GatePassed || saved.TeamID != alpha.ID {
		t.Fatal("policy or team not recorded")
	}
	status, _ = request("GET", "/api/runs/"+r.ID, bToken, nil)
	if status != 404 {
		t.Fatal("cross-team evidence exposed", status, beta.ID)
	}
	status, _ = request("GET", fmt.Sprintf("/api/runs?team=%d", alpha.ID), bToken, nil)
	if status != 403 {
		t.Fatal("cross-team filter accepted", status)
	}
	status, _ = request("GET", "/api/runs", "", nil)
	if status != 401 {
		t.Fatal("anonymous history exposed", status)
	}
	status, _ = request("POST", "/api/runs", aToken, b)
	if status != 400 {
		t.Fatal("duplicate run accepted", status)
	}
	req, _ := http.NewRequest("POST", server.URL+"/logout", nil)
	req.AddCookie(&http.Cookie{Name: "ap_session", Value: aToken})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("CSRF protection missing")
	}
	status, page := request("GET", "/", aToken, nil)
	if status != 200 || !bytes.Contains(page, []byte("Offline readiness")) || !bytes.Contains(page, []byte("View report")) {
		t.Fatal("dashboard rendering failed", status, string(page))
	}
	newToken, err := store.Rotate(ctx, alpha.ID)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = request("GET", "/api/runs", aToken, nil)
	if status != 401 {
		t.Fatal("rotated token still works")
	}
	status, _ = request("GET", "/api/runs", newToken, nil)
	if status != 200 {
		t.Fatal("new token rejected")
	}
}
