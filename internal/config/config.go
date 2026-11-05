package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const HelperImage = "ghcr.io/cenab/airgapproof-helper:0.1.0"

type Config struct {
	Version     int         `yaml:"version" json:"version"`
	Application Application `yaml:"application" json:"application"`
	Isolation   Isolation   `yaml:"isolation" json:"isolation"`
	Artifacts   Artifacts   `yaml:"artifacts" json:"artifacts"`
	Scenarios   []Scenario  `yaml:"scenarios" json:"scenarios"`
	Report      Report      `yaml:"report" json:"report"`
	BaseDir     string      `yaml:"-" json:"-"`
}
type Application struct {
	Name       string   `yaml:"name" json:"name"`
	Compose    string   `yaml:"compose" json:"compose,omitempty"`
	Kubernetes []string `yaml:"kubernetes" json:"kubernetes,omitempty"`
	NodeImage  string   `yaml:"node_image" json:"node_image,omitempty"`
}
type Isolation struct {
	Mode           string `yaml:"mode" json:"mode"`
	AllowInternal  *bool  `yaml:"allow_internal_services" json:"allow_internal_services,omitempty"`
	DenyExternal   *bool  `yaml:"deny_external_network" json:"deny_external_network,omitempty"`
	Tracing        string `yaml:"tracing" json:"tracing"`
	FailOnAttempts bool   `yaml:"fail_on_attempts" json:"fail_on_attempts"`
	VMImage        string `yaml:"vm_image" json:"vm_image,omitempty"`
	VMArch         string `yaml:"vm_arch" json:"vm_arch,omitempty"`
	VMFirmware     string `yaml:"vm_firmware" json:"vm_firmware,omitempty"`
	VMBinary       string `yaml:"vm_binary" json:"vm_binary,omitempty"`
}
type Artifacts struct {
	RequirePreloaded *bool    `yaml:"require_preloaded_images" json:"require_preloaded_images,omitempty"`
	HelperImage      string   `yaml:"helper_image" json:"helper_image"`
	Files            []string `yaml:"files" json:"files,omitempty"`
}
type Scenario struct {
	Name             string            `yaml:"name" json:"name"`
	Type             string            `yaml:"type" json:"type"`
	URL              string            `yaml:"url" json:"url,omitempty"`
	Method           string            `yaml:"method" json:"method,omitempty"`
	Headers          map[string]string `yaml:"headers" json:"headers,omitempty"`
	Body             string            `yaml:"body" json:"body,omitempty"`
	ExpectedStatus   int               `yaml:"expected_status" json:"expected_status,omitempty"`
	ExpectedContains string            `yaml:"expected_contains" json:"expected_contains,omitempty"`
	Service          string            `yaml:"service" json:"service,omitempty"`
	Command          []string          `yaml:"command" json:"command,omitempty"`
	ExpectedExitCode int               `yaml:"expected_exit_code" json:"expected_exit_code"`
	Verify           string            `yaml:"verify" json:"verify,omitempty"`
	Timeout          string            `yaml:"timeout" json:"timeout"`
}
type Report struct {
	Formats []string `yaml:"formats" json:"formats"`
}

func Load(path, compose string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, err
	}
	c.BaseDir, err = filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if compose != "" {
		c.Application.Compose, err = filepath.Abs(compose)
		if err != nil {
			return nil, err
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func Parse(data []byte) (*Config, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("profile exceeds 1 MiB")
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("profile must contain exactly one YAML document")
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return errors.New("profile version must be 1")
	}
	if (c.Application.Compose == "") == (len(c.Application.Kubernetes) == 0) {
		return errors.New("set exactly one of application.compose or application.kubernetes")
	}
	if c.Application.Name == "" {
		c.Application.Name = "Application"
	}
	if c.Isolation.Mode == "" {
		c.Isolation.Mode = "developer"
	}
	if c.Isolation.Mode != "developer" && c.Isolation.Mode != "disconnected" {
		return errors.New("isolation.mode must be developer or disconnected")
	}
	if c.Isolation.DenyExternal != nil && !*c.Isolation.DenyExternal {
		return errors.New("external networking cannot be enabled in an offline test")
	}
	if c.Isolation.AllowInternal != nil && !*c.Isolation.AllowInternal {
		return errors.New("allow_internal_services: false is unsupported")
	}
	if c.Artifacts.RequirePreloaded != nil && !*c.Artifacts.RequirePreloaded {
		return errors.New("test runs always require preloaded images; use prepare separately")
	}
	if c.Isolation.Tracing == "" {
		c.Isolation.Tracing = "auto"
	}
	if c.Isolation.Tracing != "auto" && c.Isolation.Tracing != "required" && c.Isolation.Tracing != "off" {
		return errors.New("tracing must be auto, required, or off")
	}
	if c.Isolation.FailOnAttempts {
		if c.Isolation.Tracing == "off" {
			return errors.New("fail_on_attempts requires runtime tracing")
		}
		c.Isolation.Tracing = "required"
	}
	if c.Isolation.Mode == "disconnected" && c.Isolation.VMImage == "" {
		return errors.New("disconnected mode requires isolation.vm_image; see vm prepare")
	}
	if c.Artifacts.HelperImage == "" {
		c.Artifacts.HelperImage = HelperImage
	}
	if c.Application.NodeImage == "" {
		c.Application.NodeImage = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
	}
	if len(c.Scenarios) == 0 {
		return errors.New("at least one functional scenario is required")
	}
	names := map[string]Scenario{}
	for i := range c.Scenarios {
		s := &c.Scenarios[i]
		if s.Name == "" {
			return errors.New("every scenario needs a name")
		}
		if _, ok := names[s.Name]; ok {
			return fmt.Errorf("duplicate scenario %q", s.Name)
		}
		if s.Timeout == "" {
			s.Timeout = "30s"
		}
		t, err := time.ParseDuration(s.Timeout)
		if err != nil || t <= 0 || t > 30*time.Minute {
			return fmt.Errorf("scenario %q timeout must be between 1ns and 30m", s.Name)
		}
		switch s.Type {
		case "http":
			u, err := url.Parse(s.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
				return fmt.Errorf("scenario %q requires an HTTP(S) URL without credentials", s.Name)
			}
			if s.Method == "" {
				s.Method = "GET"
			}
			if s.ExpectedStatus == 0 {
				s.ExpectedStatus = 200
			}
			if s.ExpectedStatus < 100 || s.ExpectedStatus > 599 {
				return fmt.Errorf("invalid expected_status for %q", s.Name)
			}
		case "exec":
			if s.ExpectedExitCode < 0 || s.ExpectedExitCode > 255 {
				return fmt.Errorf("scenario %q expected_exit_code must be between 0 and 255", s.Name)
			}
			if s.Service == "" || len(s.Command) == 0 {
				return fmt.Errorf("scenario %q requires a service and argv command", s.Name)
			}
		case "restart":
			if s.Service == "" || s.Verify == "" {
				return fmt.Errorf("scenario %q requires service and verify", s.Name)
			}
		default:
			return fmt.Errorf("unsupported scenario type %q", s.Type)
		}
		names[s.Name] = *s
	}
	for _, s := range c.Scenarios {
		if s.Type == "restart" {
			v, ok := names[s.Verify]
			if !ok || v.Type == "restart" {
				return fmt.Errorf("scenario %q verify must reference an HTTP or exec scenario", s.Name)
			}
		}
	}
	if len(c.Report.Formats) == 0 {
		c.Report.Formats = []string{"json", "html", "sarif"}
	}
	for _, f := range c.Report.Formats {
		if f != "json" && f != "html" && f != "sarif" {
			return fmt.Errorf("unsupported report format %q", f)
		}
	}
	return nil
}

func (c *Config) Path(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.BaseDir, path)
}

func (s Scenario) Duration() time.Duration { d, _ := time.ParseDuration(s.Timeout); return d }

func (c *Config) Scenario(name string) Scenario {
	for _, s := range c.Scenarios {
		if s.Name == name {
			return s
		}
	}
	return Scenario{}
}

func SafeRelative(path string) bool {
	return path != "" && !filepath.IsAbs(path) && path != "." && path != ".." && !strings.HasPrefix(filepath.Clean(path), ".."+string(filepath.Separator)) && !strings.Contains(path, "\\")
}
