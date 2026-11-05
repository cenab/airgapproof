package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cenab/airgapproof/internal/bundle"
	"github.com/cenab/airgapproof/internal/compose"
	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/dashboard"
	"github.com/cenab/airgapproof/internal/discovery"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/kube"
	"github.com/cenab/airgapproof/internal/report"
	"github.com/cenab/airgapproof/internal/run"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string { return e.message }
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		var e exitError
		if errors.As(err, &e) {
			os.Exit(e.code)
		}
		os.Exit(2)
	}
}
func root() *cobra.Command {
	root := &cobra.Command{Use: "airgapproof", Short: "Test defined application workflows without internet access", Version: version, SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(testCommand(), prepareCommand(), scanCommand(), bundleCommand(), vmCommand(), keygenCommand(), signCommand(), verifyCommand(), publishCommand(), serveCommand(), patchCommand())
	return root
}
func profileFlags(cmd *cobra.Command, path, composePath *string) {
	cmd.Flags().StringVar(path, "config", "airgapproof.yaml", "Offline test profile")
	cmd.Flags().StringVar(composePath, "compose", "", "Override the profile's Compose file")
}
func testCommand() *cobra.Command {
	var path, composePath, dir, revision, key string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "test", Short: "Run isolated startup, functional, and recovery checks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		c, err := config.Load(path, composePath)
		if err != nil {
			return err
		}
		if c.Isolation.Mode == "disconnected" && !cmd.Flags().Changed("timeout") {
			timeout = 20 * time.Minute
		}
		r, executionErr := run.Test(cmd.Context(), c, run.Options{Log: cmd.ErrOrStderr(), Timeout: timeout, Revision: revision})
		if r == nil {
			return executionErr
		}
		if key != "" {
			private, err := readPrivate(key)
			if err != nil {
				return err
			}
			if err = r.Sign(private); err != nil {
				return err
			}
		}
		formats := append([]string{"json"}, c.Report.Formats...)
		seen := map[string]bool{}
		unique := []string{}
		for _, f := range formats {
			if !seen[f] {
				seen[f] = true
				unique = append(unique, f)
			}
		}
		if err = r.Write(dir, unique); err != nil {
			return err
		}
		passed := 0
		for _, s := range r.Scenarios {
			if s.Passed {
				passed++
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (%d/%d workflows)\nReport: %s\n", r.Application, r.Status, passed, len(c.Scenarios), filepath.Join(dir, "report.json"))
		if r.Status != "ready" {
			return exitError{1, "offline readiness checks did not pass"}
		}
		return nil
	}}
	profileFlags(cmd, &path, &composePath)
	cmd.Flags().StringVar(&dir, "report", "airgap-report", "Report output directory")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum run duration (20m by default for disconnected VMs)")
	cmd.Flags().StringVar(&revision, "revision", "", "Application commit or release identifier")
	cmd.Flags().StringVar(&key, "sign-key", "", "Ed25519 private key file for signed evidence")
	return cmd
}
func prepareCommand() *cobra.Command {
	var path, composePath string
	var build bool
	cmd := &cobra.Command{Use: "prepare", Short: "Explicit online step: build requested images and pull missing images", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		c, err := config.Load(path, composePath)
		if err != nil {
			return err
		}
		images := []string{c.Artifacts.HelperImage}
		if c.Application.Compose != "" {
			p, err := compose.Load(cmd.Context(), c)
			if err != nil {
				return err
			}
			if build {
				if _, err = engine.Docker(cmd.Context(), "compose", "--file", c.Path(c.Application.Compose), "build"); err != nil {
					return err
				}
			}
			images = append(images, p.Images()...)
		} else {
			if build {
				return errors.New("--build applies only to Compose")
			}
			m, err := kube.Load(c)
			if err != nil {
				return err
			}
			images = append(images, m.Images...)
			images = append(images, c.Application.NodeImage)
		}
		for _, image := range images {
			if _, err := engine.Docker(cmd.Context(), "image", "inspect", image); err == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Preloaded:", image)
				continue
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Pulling:", image)
			if _, err = engine.Docker(cmd.Context(), "pull", image); err != nil {
				return err
			}
		}
		return nil
	}}
	profileFlags(cmd, &path, &composePath)
	cmd.Flags().BoolVar(&build, "build", false, "Build application images while online before checking local images")
	return cmd
}
func scanCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{Use: "scan [directory]", Short: "Find potential dependencies without executing the application", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		findings, gaps := discovery.Scan(path)
		b, err := json.MarshalIndent(map[string]any{"findings": findings, "gaps": gaps, "classification": "potential dependencies; no runtime readiness verdict"}, "", "  ")
		if err != nil {
			return err
		}
		if output != "" {
			return engine.WritePrivate(output, b)
		}
		_, err = cmd.OutOrStdout().Write(append(b, '\n'))
		return err
	}}
	cmd.Flags().StringVar(&output, "output", "", "Write findings to a JSON file")
	return cmd
}
func bundleCommand() *cobra.Command {
	root := &cobra.Command{Use: "bundle", Short: "Export, verify, and load checksummed offline artifacts"}
	var path, composePath, output string
	export := &cobra.Command{Use: "export", Short: "Export preloaded images and declared deployment artifacts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if output == "" {
			return errors.New("--output is required")
		}
		c, err := config.Load(path, composePath)
		if err != nil {
			return err
		}
		if err = bundle.Export(cmd.Context(), c, output); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bundle exported:", output)
		return nil
	}}
	profileFlags(export, &path, &composePath)
	export.Flags().StringVar(&output, "output", "", "New bundle directory")
	verify := &cobra.Command{Use: "verify directory", Short: "Verify all file paths, sizes, and SHA-256 checksums", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		m, err := bundle.Verify(args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Verified %d files and %d image identities\n", len(m.Files), len(m.Images))
		return nil
	}}
	load := &cobra.Command{Use: "load directory", Short: "Verify the bundle, import images, and check their identities", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := bundle.Load(cmd.Context(), args[0]); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bundle images loaded and verified")
		return nil
	}}
	root.AddCommand(export, verify, load)
	return root
}
func vmCommand() *cobra.Command {
	var image, output, arch, firmware string
	root := &cobra.Command{Use: "vm", Short: "Prepare disposable disconnected QEMU guests"}
	prepare := &cobra.Command{Use: "prepare", Short: "Provision Docker in a supplied Ubuntu cloud image while online", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if image == "" || output == "" {
			return errors.New("--cloud-image and --output are required")
		}
		return run.VMPrepare(cmd.Context(), image, output, arch, firmware, run.Options{Log: cmd.ErrOrStderr()})
	}}
	prepare.Flags().StringVar(&image, "cloud-image", "", "Verified Ubuntu cloud QCOW2 image")
	prepare.Flags().StringVar(&output, "output", "", "New prepared QCOW2 image")
	prepare.Flags().StringVar(&arch, "arch", "", "Guest architecture: amd64 or arm64 (default host)")
	prepare.Flags().StringVar(&firmware, "firmware", "", "UEFI firmware file; required for arm64")
	root.AddCommand(prepare)
	return root
}
func keygenCommand() *cobra.Command {
	var path string
	cmd := &cobra.Command{Use: "keygen", Short: "Create Ed25519 evidence signing keys", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if path == "" {
			return errors.New("--output is required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if _, err = os.Stat(path + ".pub"); !os.IsNotExist(err) {
			return errors.New("public key output already exists")
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.WriteFile(path+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Private key:", path, "\nPublic key:", path+".pub")
		return nil
	}}
	cmd.Flags().StringVar(&path, "output", "", "New private key file (public key adds .pub)")
	return cmd
}
func readPrivate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(key), nil
}
func signCommand() *cobra.Command {
	var key, output string
	cmd := &cobra.Command{Use: "sign report.json", Short: "Sign report contents without changing the original report", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if key == "" || output == "" {
			return errors.New("--key and --output are required")
		}
		r, err := report.Read(args[0])
		if err != nil {
			return err
		}
		private, err := readPrivate(key)
		if err != nil {
			return err
		}
		if err = r.Sign(private); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		return engine.WritePrivate(output, b)
	}}
	cmd.Flags().StringVar(&key, "key", "", "Private signing key")
	cmd.Flags().StringVar(&output, "output", "", "Signed JSON report output")
	return cmd
}
func verifyCommand() *cobra.Command {
	var key string
	cmd := &cobra.Command{Use: "verify report.json", Short: "Verify signed evidence against an explicitly trusted public key", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if key == "" {
			return errors.New("--public-key is required")
		}
		r, err := report.Read(args[0])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(key)
		if err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("invalid public key")
		}
		if err = r.Verify(pub); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Signature verified against trusted key")
		return nil
	}}
	cmd.Flags().StringVar(&key, "public-key", "", "Trusted public key file")
	return cmd
}
func publishCommand() *cobra.Command {
	var server, tokenEnv string
	cmd := &cobra.Command{Use: "publish report.json", Short: "Upload evidence and return the organization's policy gate result", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		r, err := report.Read(args[0])
		if err != nil {
			return err
		}
		u, err := url.Parse(server)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("--server must be a dashboard base URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return errors.New("dashboard uploads require HTTPS except on loopback")
		}
		token := os.Getenv(tokenEnv)
		if len(token) < 32 {
			return fmt.Errorf("set %s to a team token", tokenEnv)
		}
		b, _ := json.Marshal(r)
		req, err := http.NewRequestWithContext(cmd.Context(), "POST", strings.TrimRight(server, "/")+"/api/runs", bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		client := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("dashboard redirects are not followed") }}
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("dashboard upload failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 201 {
			return fmt.Errorf("dashboard rejected the upload (HTTP %d)", resp.StatusCode)
		}
		var saved dashboard.Run
		if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&saved); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Stored run %s; policy passed: %t\n", saved.ID, saved.GatePassed)
		for _, reason := range saved.Decision.Reasons {
			fmt.Fprintln(cmd.OutOrStdout(), reason)
		}
		if !saved.GatePassed {
			return exitError{1, "organizational policy did not pass"}
		}
		return nil
	}}
	cmd.Flags().StringVar(&server, "server", "", "Dashboard base URL")
	cmd.Flags().StringVar(&tokenEnv, "token-env", "AIRGAPPROOF_TOKEN", "Environment variable containing the team token")
	return cmd
}
func serveCommand() *cobra.Command {
	var listen, url, dbEnv, adminEnv string
	cmd := &cobra.Command{Use: "serve", Short: "Run the private PostgreSQL-backed evidence dashboard", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		db := os.Getenv(dbEnv)
		if db == "" {
			return fmt.Errorf("set %s", dbEnv)
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "Dashboard listening on", listen)
		return dashboard.Serve(cmd.Context(), listen, db, os.Getenv(adminEnv), url)
	}}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	cmd.Flags().StringVar(&url, "public-url", "http://127.0.0.1:8080", "Public origin used for secure cookies and CSRF checks")
	cmd.Flags().StringVar(&dbEnv, "database-url-env", "AIRGAPPROOF_DATABASE_URL", "Database URL environment variable")
	cmd.Flags().StringVar(&adminEnv, "admin-token-env", "AIRGAPPROOF_ADMIN_TOKEN", "Admin token environment variable")
	return cmd
}
func patchCommand() *cobra.Command {
	var dockerfile, model, output string
	cmd := &cobra.Command{Use: "patch-model", Short: "Propose a reviewable Dockerfile patch for an explicitly supplied local model", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if dockerfile == "" || model == "" || output == "" {
			return errors.New("--dockerfile, --model, and --output are required")
		}
		if !config.SafeRelative(model) || strings.ContainsAny(model, "*?[]\n\r") {
			return errors.New("model must be a literal relative path inside the Docker build context")
		}
		b, err := os.ReadFile(dockerfile)
		if err != nil {
			return err
		}
		if !bytes.Contains(bytes.ToUpper(b), []byte("FROM ")) {
			return errors.New("Dockerfile must contain a FROM instruction")
		}
		source, _ := json.Marshal([]string{filepath.ToSlash(model), "/opt/airgapproof/model/"})
		lines := strings.Count(string(b), "\n")
		if len(b) > 0 && b[len(b)-1] != '\n' {
			return errors.New("Dockerfile must end with a newline")
		}
		patch := fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d,0 +%d,3 @@\n+COPY %s\n+ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1\n+# Configure the application to load /opt/airgapproof/model and rerun its workflows.\n", filepath.Base(dockerfile), filepath.Base(dockerfile), lines, lines+1, source)
		if err = engine.WritePrivate(output, []byte(patch)); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Proposed patch:", output, "(review artifact permissions, build context, and application model configuration before applying)")
		return nil
	}}
	cmd.Flags().StringVar(&dockerfile, "dockerfile", "", "Dockerfile to inspect")
	cmd.Flags().StringVar(&model, "model", "", "Explicit model path relative to the Docker build context")
	cmd.Flags().StringVar(&output, "output", "", "New patch file")
	return cmd
}
