package discovery

import (
	"bufio"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cenab/airgapproof/internal/report"
)

var endpoints = regexp.MustCompile(`https?://[^\s"'<>\x60]+`)

func Scan(root string) ([]report.Finding, []string) {
	findings := []report.Finding{}
	gaps := []string{}
	total := int64(0)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "reports" || name == "dist" || name == "bin" {
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := filepath.Ext(name)
		if name != "Dockerfile" && ext != ".py" && ext != ".js" && ext != ".ts" && ext != ".yaml" && ext != ".yml" && ext != ".toml" && ext != ".json" && ext != ".env" && ext != ".sh" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 2<<20 || total+info.Size() > 20<<20 {
			gaps = append(gaps, "Static scan skipped oversized files or reached its 20 MiB budget.")
			return nil
		}
		total += info.Size()
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 2<<20)
		line := 0
		rel, _ := filepath.Rel(root, path)
		add := func(rule, message, fix string) {
			if len(findings) < 1000 {
				findings = append(findings, report.Finding{Rule: rule, Severity: "warning", Category: "potential_dependency", Message: message, Remediation: fix, Path: filepath.ToSlash(rel), Line: line})
			}
		}
		for s.Scan() {
			line++
			text := s.Text()
			lower := strings.ToLower(text)
			for _, match := range endpoints.FindAllString(text, -1) {
				u, err := url.Parse(match)
				if err == nil && u.Hostname() != "" && u.Hostname() != "localhost" {
					add("static.external-url", "Potential network endpoint: "+u.Hostname(), "Provide an offline alternative or verify this endpoint is optional in a functional scenario.")
				}
			}
			if strings.Contains(lower, "from_pretrained(") || strings.Contains(lower, "snapshot_download(") || strings.Contains(lower, "hf_hub_download(") {
				add("static.model-download", "Model loader can fetch weights when local files are absent.", "Package a versioned model artifact, use a local path, and enable local_files_only.")
			}
			if strings.Contains(lower, "pip install") || strings.Contains(lower, "npm install") || strings.Contains(lower, "apt-get") || strings.Contains(lower, "apk add") {
				add("static.package-download", "Package installation may require an external package repository.", "Build dependencies into the image before exporting the offline bundle.")
			}
			if strings.Contains(lower, "sentry") || strings.Contains(lower, "datadog") || strings.Contains(lower, "telemetry") {
				add("static.telemetry", "Potential external monitoring or telemetry dependency.", "Disable or redirect telemetry in the offline deployment profile.")
			}
			if strings.Contains(lower, "openid") || strings.Contains(lower, "oauth") || strings.Contains(lower, "license_server") {
				add("static.auth-license", "Potential external authentication or license dependency.", "Configure a local identity provider or an authorized offline licensing mechanism.")
			}
		}
		return s.Err()
	})
	if err != nil {
		gaps = append(gaps, "Static scan was incomplete: a file could not be read.")
	}
	return findings, gaps
}
