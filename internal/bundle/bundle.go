package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cenab/airgapproof/internal/compose"
	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/kube"
	"go.yaml.in/yaml/v3"
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Image struct {
	Reference string `json:"reference"`
	ID        string `json:"id"`
}
type Manifest struct {
	Version int     `json:"version"`
	Images  []Image `json:"images"`
	Files   []File  `json:"files"`
}

const ImagePrefix = "airgapproof.local/image:"

func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func Export(ctx context.Context, c *config.Config, output string) error {
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		return errors.New("bundle output must not already exist")
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(output), ".airgap-bundle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	copyConfig := *c
	copyConfig.BaseDir = ""
	copyConfig.Isolation.Mode = "developer"
	copyConfig.Isolation.VMImage = ""
	copyConfig.Isolation.VMFirmware = ""
	copyConfig.Isolation.VMBinary = ""
	images := []string{c.Artifacts.HelperImage}
	var composition *compose.Project
	var workload *kube.Manifest
	if c.Application.Compose != "" {
		p, err := compose.Load(ctx, c)
		if err != nil {
			return err
		}
		composition = p
		images = append(images, p.Images()...)
		copyArtifact := func(source string) (string, error) {
			rel, err := filepath.Rel(c.BaseDir, source)
			if err != nil || !config.SafeRelative(rel) {
				return "", errors.New("bundle artifacts must be within the profile directory")
			}
			if reserved(rel) {
				return "", fmt.Errorf("artifact path conflicts with bundle metadata: %s", rel)
			}
			if err = copyTree(source, filepath.Join(dir, rel)); err != nil {
				return "", err
			}
			return filepath.ToSlash(rel), nil
		}
		for _, value := range p.Services {
			s := value.(map[string]any)
			delete(s, "build")
			if volumes, ok := s["volumes"].([]any); ok {
				for _, v := range volumes {
					m := v.(map[string]any)
					if m["type"] == "bind" {
						rel, err := copyArtifact(m["source"].(string))
						if err != nil {
							return err
						}
						m["source"] = "./" + rel
					}
				}
			}
		}
		for _, kind := range []string{"configs", "secrets"} {
			if values, ok := p.Model[kind].(map[string]any); ok {
				for _, v := range values {
					m := v.(map[string]any)
					if file, ok := m["file"].(string); ok {
						rel, err := copyArtifact(file)
						if err != nil {
							return err
						}
						m["file"] = "./" + rel
					}
				}
			}
		}
		copyConfig.Application.Compose = "compose.json"
	} else {
		m, err := kube.Load(c)
		if err != nil {
			return err
		}
		workload = m
		images = append(images, m.Images...)
		images = append(images, c.Application.NodeImage)
		copyConfig.Application.Kubernetes = []string{"kubernetes.json"}
	}
	for _, path := range c.Artifacts.Files {
		if !config.SafeRelative(path) {
			return fmt.Errorf("artifact file must be relative: %s", path)
		}
		if reserved(path) {
			return fmt.Errorf("artifact path conflicts with bundle metadata: %s", path)
		}
		if err = copyTree(c.Path(path), filepath.Join(dir, path)); err != nil {
			return err
		}
	}
	manifest := Manifest{Version: 1}
	seen := map[string]bool{}
	seenIDs := map[string]bool{}
	archiveBytes := engine.DiskReserve
	unique := []string{}
	for _, image := range images {
		if seen[image] {
			continue
		}
		seen[image] = true
		b, err := engine.Docker(ctx, "image", "inspect", "--format", "{{.Id}}", image)
		if err != nil {
			return fmt.Errorf("image is not preloaded: %s", image)
		}
		unique = append(unique, image)
		id := strings.TrimSpace(string(b))
		manifest.Images = append(manifest.Images, Image{Reference: image, ID: id})
		if !seenIDs[id] {
			b, err = engine.Docker(ctx, "image", "inspect", "--format", "{{.Size}}", image)
			if err != nil {
				return err
			}
			size, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 63)
			if err != nil || size > ^uint64(0)-archiveBytes {
				return fmt.Errorf("invalid image size: %s", image)
			}
			archiveBytes += size
			seenIDs[id] = true
		}
	}
	ids := map[string]string{}
	for _, image := range manifest.Images {
		ids[image.Reference] = ImagePrefix + strings.TrimPrefix(image.ID, "sha256:")
	}
	copyConfig.Artifacts.HelperImage = ids[c.Artifacts.HelperImage]
	// Registry digest metadata can be lost; content-derived aliases also work with Kubernetes image-name parsing.
	if composition != nil {
		for _, value := range composition.Services {
			s := value.(map[string]any)
			s["image"] = ids[s["image"].(string)]
		}
		b, err := json.MarshalIndent(composition.Model, "", "  ")
		if err != nil {
			return err
		}
		if err = engine.WritePrivate(filepath.Join(dir, "compose.json"), b); err != nil {
			return err
		}
	} else {
		copyConfig.Application.NodeImage = ids[c.Application.NodeImage]
		for _, object := range workload.Objects {
			spec := kube.PodSpec(object)
			for _, key := range []string{"containers", "initContainers"} {
				if containers, ok := spec[key].([]any); ok {
					for _, value := range containers {
						ct := value.(map[string]any)
						ct["image"] = ids[ct["image"].(string)]
					}
				}
			}
		}
		b, err := json.MarshalIndent(workload.List(), "", "  ")
		if err != nil {
			return err
		}
		if err = engine.WritePrivate(filepath.Join(dir, "kubernetes.json"), b); err != nil {
			return err
		}
	}
	b, err := yaml.Marshal(copyConfig)
	if err != nil {
		return err
	}
	if err = engine.WritePrivate(filepath.Join(dir, "airgapproof.yaml"), b); err != nil {
		return err
	}
	if err = engine.RequireSpace(dir, archiveBytes); err != nil {
		return err
	}
	if _, err = engine.Docker(ctx, append([]string{"image", "save", "--output", filepath.Join(dir, "images.tar")}, unique...)...); err != nil {
		return err
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		hash, n, err := HashFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		manifest.Files = append(manifest.Files, File{Path: filepath.ToSlash(rel), SHA256: hash, Size: n})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	b, _ = json.MarshalIndent(manifest, "", "  ")
	if err = engine.WritePrivate(filepath.Join(dir, "manifest.json"), b); err != nil {
		return err
	}
	return os.Rename(dir, output)
}
func Verify(dir string) (*Manifest, error) {
	var absErr error
	dir, absErr = filepath.Abs(dir)
	if absErr != nil {
		return nil, absErr
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	if len(b) > 4<<20 {
		return nil, errors.New("bundle manifest is too large")
	}
	var m Manifest
	if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Version != 1 || len(m.Files) == 0 || len(m.Images) == 0 {
		return nil, errors.New("invalid bundle manifest")
	}
	seen := map[string]bool{"manifest.json": true}
	for _, f := range m.Files {
		if !config.SafeRelative(f.Path) || seen[f.Path] {
			return nil, errors.New("invalid or duplicate bundle path")
		}
		seen[f.Path] = true
		path := filepath.Join(dir, f.Path)
		if err := noSymlinks(dir, path); err != nil {
			return nil, err
		}
		hash, n, err := HashFile(path)
		if err != nil || hash != f.SHA256 || n != f.Size {
			return nil, fmt.Errorf("bundle checksum mismatch: %s", f.Path)
		}
	}
	for _, required := range []string{"airgapproof.yaml", "images.tar"} {
		if !seen[required] {
			return nil, fmt.Errorf("bundle is missing %s", required)
		}
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if !seen[filepath.ToSlash(rel)] {
			return fmt.Errorf("unlisted bundle file: %s", rel)
		}
		return nil
	})
	return &m, err
}
func Load(ctx context.Context, dir string) error {
	m, err := Verify(dir)
	if err != nil {
		return err
	}
	if _, err = engine.Docker(ctx, "image", "load", "--input", filepath.Join(dir, "images.tar")); err != nil {
		return err
	}
	for _, image := range m.Images {
		b, err := engine.Docker(ctx, "image", "inspect", "--format", "{{.Id}}", image.ID)
		if err != nil || strings.TrimSpace(string(b)) != image.ID {
			return fmt.Errorf("loaded image identity mismatch: %s", image.Reference)
		}
		if _, err = engine.Docker(ctx, "image", "tag", image.ID, ImagePrefix+strings.TrimPrefix(image.ID, "sha256:")); err != nil {
			return err
		}
	}
	return nil
}
func noSymlinks(base, path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bundle cannot contain symlinks")
		}
		if path == base {
			break
		}
		parent := filepath.Dir(path)
		if parent == path {
			return errors.New("invalid bundle root")
		}
		path = parent
	}
	return nil
}
func copyTree(source, dest string) error {
	return filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("bundle artifacts must be regular files or directories")
		}
		rel, _ := filepath.Rel(source, path)
		target := filepath.Join(dest, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err = engine.RequireSpace(filepath.Dir(target), uint64(info.Size())+engine.DiskReserve); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if os.IsExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}
func reserved(path string) bool {
	switch filepath.ToSlash(filepath.Clean(path)) {
	case "manifest.json", "compose.json", "kubernetes.json", "airgapproof.yaml", "images.tar":
		return true
	}
	return false
}
