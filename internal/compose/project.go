package compose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/report"
	composecli "github.com/compose-spec/compose-go/v2/cli"
	"go.yaml.in/yaml/v3"
)

type Project struct {
	Model    map[string]any
	Services map[string]any
	Networks map[string]any
	BaseDir  string
	Hash     string
}

func Load(ctx context.Context, c *config.Config) (*Project, error) {
	path := c.Path(c.Application.Compose)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err = yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if raw["include"] != nil {
		return nil, errors.New("Compose include is unsupported; supply a self-contained Compose file")
	}
	if services, ok := raw["services"].(map[string]any); ok {
		for name, value := range services {
			if s, ok := value.(map[string]any); ok && s["extends"] != nil {
				return nil, fmt.Errorf("service %s: extends is unsupported; flatten the Compose file first", name)
			}
		}
	}
	opts, err := composecli.NewProjectOptions([]string{path}, composecli.WithName("airgapproof"), composecli.WithOsEnv, composecli.WithEnvFiles(), composecli.WithDotEnv, composecli.WithDiscardEnvFile)
	if err != nil {
		return nil, err
	}
	project, err := composecli.ProjectFromOptions(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("load Compose model: %w", err)
	}
	b, err = project.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var model map[string]any
	if err = json.Unmarshal(b, &model); err != nil {
		return nil, err
	}
	services, _ := model["services"].(map[string]any)
	networks, _ := model["networks"].(map[string]any)
	if len(services) == 0 {
		return nil, errors.New("Compose has no active services")
	}
	p := &Project{Model: model, Services: services, Networks: networks, BaseDir: c.BaseDir, Hash: report.Hash(b)}
	return p, p.Validate()
}

var allowedService = map[string]bool{}

func init() {
	for _, key := range strings.Fields("image build pull_policy command entrypoint environment env_file working_dir user hostname domainname healthcheck depends_on networks volumes configs secrets ports expose restart init read_only tmpfs cap_drop security_opt mem_limit mem_reservation memswap_limit cpus cpu_shares ulimits stop_grace_period stop_signal logging labels container_name platform profiles scale deploy shm_size stdin_open tty attach") {
		allowedService[key] = true
	}
}
func (p *Project) Validate() error {
	for name, value := range p.Services {
		s := value.(map[string]any)
		for key := range s {
			if !allowedService[key] {
				return fmt.Errorf("service %s: unsupported or unsafe setting %s", name, key)
			}
		}
		if image, _ := s["image"].(string); image == "" {
			return fmt.Errorf("service %s needs an explicit prebuilt image", name)
		}
		if scale, ok := s["scale"].(float64); ok && scale != 1 {
			return fmt.Errorf("service %s: replicas other than one are unsupported", name)
		}
		if dep, ok := s["deploy"].(map[string]any); ok {
			for k, v := range dep {
				if k == "replicas" && v == float64(1) {
					continue
				}
				if k != "resources" {
					return fmt.Errorf("service %s: unsupported deploy.%s", name, k)
				}
			}
		}
		if log, ok := s["logging"].(map[string]any); ok {
			driver, _ := log["driver"].(string)
			if driver != "" && driver != "local" && driver != "json-file" && driver != "none" {
				return fmt.Errorf("service %s: remote logging drivers are forbidden", name)
			}
		}
		if sec, ok := s["security_opt"].([]any); ok {
			for _, x := range sec {
				v := fmt.Sprint(x)
				if v != "no-new-privileges:true" && v != "no-new-privileges" {
					return fmt.Errorf("service %s: custom security_opt is unsupported", name)
				}
			}
		}
		if volumes, ok := s["volumes"].([]any); ok {
			for _, v := range volumes {
				m := v.(map[string]any)
				switch m["type"] {
				case "bind":
					if m["read_only"] != true {
						return fmt.Errorf("service %s: host binds must be read-only", name)
					}
					if err := SafeFile(p.BaseDir, fmt.Sprint(m["source"])); err != nil {
						return fmt.Errorf("service %s: %w", name, err)
					}
				case "volume", "tmpfs":
				default:
					return fmt.Errorf("service %s: unsupported mount type", name)
				}
			}
		}
		if nets, ok := s["networks"].(map[string]any); ok {
			for _, v := range nets {
				if v == nil {
					continue
				}
				for key := range v.(map[string]any) {
					if key != "aliases" && key != "priority" {
						return fmt.Errorf("service %s: custom network addresses or driver options are unsupported", name)
					}
				}
			}
		}
	}
	for name, value := range p.Networks {
		n := value.(map[string]any)
		if n["external"] == true {
			return fmt.Errorf("network %s: external attachments are forbidden", name)
		}
		if d, _ := n["driver"].(string); d != "" && d != "bridge" {
			return fmt.Errorf("network %s requires bridge driver", name)
		}
		for _, key := range []string{"driver_opts", "ipam", "enable_ipv6"} {
			if v, ok := n[key]; ok && v != false && !emptyMapping(v) {
				return fmt.Errorf("network %s: custom %s is unsupported", name, key)
			}
		}
	}
	if volumes, ok := p.Model["volumes"].(map[string]any); ok {
		for name, v := range volumes {
			if v == nil {
				continue
			}
			for key, value := range v.(map[string]any) {
				if key == "name" || key == "labels" {
					continue
				}
				if key == "driver" && value == "local" {
					continue
				}
				if key == "external" && value == false {
					continue
				}
				return fmt.Errorf("volume %s: external volumes and driver options are forbidden", name)
			}
		}
	}
	for _, kind := range []string{"configs", "secrets"} {
		if values, ok := p.Model[kind].(map[string]any); ok {
			for name, v := range values {
				m := v.(map[string]any)
				if m["external"] == true {
					return fmt.Errorf("%s %s: external resources are unsupported", kind, name)
				}
				if file, ok := m["file"].(string); ok {
					if err := SafeFile(p.BaseDir, file); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func emptyMapping(v any) bool { m, ok := v.(map[string]any); return ok && len(m) == 0 }
func SafeFile(base, path string) error {
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || !config.SafeRelative(rel) {
		return errors.New("mounted artifacts must be inside the profile directory and cannot be its root")
	}
	return filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("mounted artifacts cannot contain symlinks, sockets, or devices")
		}
		return nil
	})
}
func (p *Project) Names() []string {
	names := []string{}
	for n := range p.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func (p *Project) Images() []string {
	seen := map[string]bool{}
	images := []string{}
	for _, n := range p.Names() {
		image := p.Services[n].(map[string]any)["image"].(string)
		if !seen[image] {
			images = append(images, image)
			seen[image] = true
		}
	}
	return images
}
func (p *Project) Harden(project string, networks map[string]string, dns []string) {
	p.Model["name"] = project
	for name, value := range p.Services {
		s := value.(map[string]any)
		delete(s, "build")
		delete(s, "container_name")
		delete(s, "ports")
		delete(s, "profiles")
		s["pull_policy"] = "never"
		s["restart"] = "no"
		s["dns"] = dns
		s["dns_opt"] = []string{"timeout:1", "attempts:1"}
		s["security_opt"] = []string{"no-new-privileges:true"}
		drops, _ := s["cap_drop"].([]any)
		s["cap_drop"] = append(drops, "NET_RAW")
		labels, _ := s["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		labels["airgapproof.run"] = project
		labels["airgapproof.service"] = name
		s["labels"] = labels
		if s["logging"] == nil {
			s["logging"] = map[string]any{"driver": "local", "options": map[string]string{"max-size": "1m", "max-file": "2"}}
		}
	}
	nets := map[string]any{}
	for key, name := range networks {
		nets[key] = map[string]any{"name": name, "external": true}
	}
	p.Model["networks"] = nets
	if vols, ok := p.Model["volumes"].(map[string]any); ok {
		for name, v := range vols {
			if v == nil {
				v = map[string]any{}
				vols[name] = v
			}
			m := v.(map[string]any)
			m["name"] = project + "_" + name
			m["labels"] = map[string]string{"airgapproof.run": project}
		}
	}
}
