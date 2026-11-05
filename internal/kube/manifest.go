package kube

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/cenab/airgapproof/internal/config"
	"go.yaml.in/yaml/v3"
)

type Manifest struct {
	Objects []map[string]any
	Images  []string
}

func Load(c *config.Config) (*Manifest, error) {
	m := &Manifest{}
	for _, path := range c.Application.Kubernetes {
		f, err := os.Open(c.Path(path))
		if err != nil {
			return nil, err
		}
		d := yaml.NewDecoder(f)
		for {
			var o map[string]any
			err = d.Decode(&o)
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, err
			}
			if len(o) > 0 {
				if err = m.add(o); err != nil {
					f.Close()
					return nil, err
				}
			}
		}
		f.Close()
	}
	if len(m.Objects) == 0 {
		return nil, errors.New("no Kubernetes objects")
	}
	return m, m.Validate()
}
func (m *Manifest) add(o map[string]any) error {
	if o["kind"] == "List" {
		items, ok := o["items"].([]any)
		if !ok {
			return errors.New("invalid Kubernetes List")
		}
		for _, item := range items {
			v, ok := item.(map[string]any)
			if !ok {
				return errors.New("invalid Kubernetes List item")
			}
			if v["kind"] == "List" {
				return errors.New("nested Lists are unsupported")
			}
			m.Objects = append(m.Objects, v)
		}
	} else {
		m.Objects = append(m.Objects, o)
	}
	return nil
}
func PodSpec(o map[string]any) map[string]any {
	spec, _ := o["spec"].(map[string]any)
	if o["kind"] == "Pod" {
		return spec
	}
	if t, ok := spec["template"].(map[string]any); ok {
		p, _ := t["spec"].(map[string]any)
		return p
	}
	return nil
}
func (m *Manifest) Validate() error {
	seen := map[string]bool{}
	images := map[string]bool{}
	for _, o := range m.Objects {
		kind, _ := o["kind"].(string)
		api, _ := o["apiVersion"].(string)
		switch kind {
		case "Pod", "Service", "ConfigMap", "Secret", "PersistentVolumeClaim":
			if api != "v1" {
				return errors.New("unsupported Kubernetes API version")
			}
		case "Deployment", "StatefulSet":
			if api != "apps/v1" {
				return errors.New("unsupported workload API version")
			}
		case "Job":
			if api != "batch/v1" {
				return errors.New("unsupported Job API version")
			}
		case "NetworkPolicy":
			if api != "networking.k8s.io/v1" {
				return errors.New("unsupported policy API version")
			}
		default:
			return fmt.Errorf("unsupported Kubernetes kind %q; cluster-scoped objects, webhooks, custom resources, and external controllers are forbidden", kind)
		}
		meta, ok := o["metadata"].(map[string]any)
		if !ok || meta["name"] == nil {
			return errors.New("every Kubernetes object needs metadata.name")
		}
		identity := kind + "/" + fmt.Sprint(meta["name"])
		if seen[identity] {
			return fmt.Errorf("duplicate Kubernetes object %s", identity)
		}
		seen[identity] = true
		if annotations, ok := meta["annotations"].(map[string]any); ok && len(annotations) > 0 {
			return fmt.Errorf("%s: annotations that can activate external controllers are unsupported", identity)
		}
		if kind == "Service" {
			spec, _ := o["spec"].(map[string]any)
			if t := spec["type"]; t != nil && t != "ClusterIP" {
				return fmt.Errorf("%s: only ClusterIP services are supported", identity)
			}
			if spec["externalIPs"] != nil || spec["externalName"] != nil {
				return fmt.Errorf("%s: external services are forbidden", identity)
			}
		}
		if kind == "PersistentVolumeClaim" {
			spec, _ := o["spec"].(map[string]any)
			if spec["volumeName"] != nil || spec["selector"] != nil || spec["dataSource"] != nil || spec["dataSourceRef"] != nil {
				return fmt.Errorf("%s: external volume bindings are forbidden", identity)
			}
		}
		p := PodSpec(o)
		if p == nil {
			if kind == "Pod" || kind == "Deployment" || kind == "StatefulSet" || kind == "Job" {
				return fmt.Errorf("%s: a valid pod spec is required", identity)
			}
			continue
		}
		if containers, ok := p["containers"].([]any); !ok || len(containers) == 0 {
			return fmt.Errorf("%s: a nonempty containers list is required", identity)
		}
		for _, key := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"} {
			if p[key] == true {
				return fmt.Errorf("%s: %s is forbidden", identity, key)
			}
		}
		for _, key := range []string{"hostAliases", "dnsConfig", "nodeName", "imagePullSecrets", "ephemeralContainers"} {
			if p[key] != nil {
				return fmt.Errorf("%s: %s is unsupported", identity, key)
			}
		}
		if d := p["dnsPolicy"]; d != nil && d != "ClusterFirst" {
			return fmt.Errorf("%s: custom DNS policy is unsupported", identity)
		}
		if s, ok := p["securityContext"].(map[string]any); ok {
			if s["sysctls"] != nil || s["seLinuxOptions"] != nil || s["windowsOptions"] != nil {
				return fmt.Errorf("%s: custom kernel security settings are unsupported", identity)
			}
		}
		if volumes, ok := p["volumes"].([]any); ok {
			for _, v := range volumes {
				volume, ok := v.(map[string]any)
				if !ok {
					return fmt.Errorf("%s: invalid volume", identity)
				}
				for key := range volume {
					switch key {
					case "name", "emptyDir", "configMap", "secret", "persistentVolumeClaim":
					default:
						return fmt.Errorf("%s: unsupported volume source %s", identity, key)
					}
				}
			}
		}
		for _, key := range []string{"containers", "initContainers"} {
			if p[key] != nil {
				if _, ok := p[key].([]any); !ok {
					return fmt.Errorf("%s: %s must be a list", identity, key)
				}
			}
			if containers, ok := p[key].([]any); ok {
				for _, v := range containers {
					ct, ok := v.(map[string]any)
					if !ok {
						return fmt.Errorf("%s: invalid container", identity)
					}
					image, _ := ct["image"].(string)
					if image == "" {
						return fmt.Errorf("%s: container image is required", identity)
					}
					images[image] = true
					if ports, ok := ct["ports"].([]any); ok {
						for _, port := range ports {
							portMap, ok := port.(map[string]any)
							if !ok {
								return fmt.Errorf("%s: invalid port", identity)
							}
							if portMap["hostPort"] != nil {
								return fmt.Errorf("%s: host ports are forbidden", identity)
							}
						}
					}
					if sec, ok := ct["securityContext"].(map[string]any); ok {
						if sec["privileged"] == true || sec["allowPrivilegeEscalation"] == true || sec["procMount"] != nil {
							return fmt.Errorf("%s: elevated container privileges are forbidden", identity)
						}
						if caps, ok := sec["capabilities"].(map[string]any); ok && caps["add"] != nil {
							return fmt.Errorf("%s: added capabilities are forbidden", identity)
						}
						if sec["seccompProfile"] != nil || sec["appArmorProfile"] != nil {
							return fmt.Errorf("%s: custom security profiles are unsupported", identity)
						}
					}
				}
			}
		}
	}
	m.Images = nil
	for image := range images {
		m.Images = append(m.Images, image)
	}
	sort.Strings(m.Images)
	if len(m.Images) == 0 {
		return errors.New("at least one workload is required")
	}
	return nil
}
func (m *Manifest) Harden(namespace string) {
	for _, o := range m.Objects {
		meta := o["metadata"].(map[string]any)
		meta["namespace"] = namespace
		p := PodSpec(o)
		if p == nil {
			continue
		}
		p["automountServiceAccountToken"] = false
		p["dnsPolicy"] = "ClusterFirst"
		for _, key := range []string{"containers", "initContainers"} {
			if containers, ok := p[key].([]any); ok {
				for _, v := range containers {
					ct := v.(map[string]any)
					ct["imagePullPolicy"] = "Never"
					sec, _ := ct["securityContext"].(map[string]any)
					if sec == nil {
						sec = map[string]any{}
					}
					sec["allowPrivilegeEscalation"] = false
					sec["seccompProfile"] = map[string]string{"type": "RuntimeDefault"}
					caps, _ := sec["capabilities"].(map[string]any)
					if caps == nil {
						caps = map[string]any{}
					}
					drop, _ := caps["drop"].([]any)
					caps["drop"] = append(drop, "NET_RAW")
					sec["capabilities"] = caps
					ct["securityContext"] = sec
				}
			}
		}
	}
}
func (m *Manifest) List() map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "List", "items": m.Objects}
}
