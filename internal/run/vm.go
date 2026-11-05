package run

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cenab/airgapproof/internal/bundle"
	"github.com/cenab/airgapproof/internal/config"
	"github.com/cenab/airgapproof/internal/engine"
	"github.com/cenab/airgapproof/internal/report"
)

func QEMUArgs(disk, seed, arch, firmware string, online bool) (string, []string, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != "arm64" && arch != "amd64" {
		return "", nil, errors.New("VM architecture must be arm64 or amd64")
	}
	binary := "qemu-system-x86_64"
	machine := "q35"
	cpu := "max"
	if arch == "arm64" {
		binary = "qemu-system-aarch64"
		machine = "virt"
		cpu = "cortex-a72"
		if firmware == "" {
			return "", nil, errors.New("arm64 VMs require isolation.vm_firmware pointing to QEMU's edk2-aarch64-code.fd")
		}
	}
	accel := "tcg"
	if arch == runtime.GOARCH {
		if runtime.GOOS == "darwin" {
			accel = "hvf"
			cpu = "host"
		} else if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
			f.Close()
			accel = "kvm"
			cpu = "host"
		}
	}
	args := []string{"-machine", machine, "-accel", accel, "-cpu", cpu, "-smp", "4", "-m", "4096", "-nographic", "-no-reboot", "-monitor", "none", "-drive", "file=" + disk + ",if=virtio,format=qcow2", "-drive", "file=" + seed + ",if=virtio,format=raw,readonly=on"}
	if firmware != "" {
		args = append(args, "-bios", firmware)
	}
	if online {
		args = append(args, "-nic", "user,model=virtio-net-pci")
	} else {
		args = append(args, "-nic", "none")
	}
	return binary, args, nil
}
func seedISO(ctx context.Context, dir, userData, id string) (string, error) {
	if err := engine.WritePrivate(filepath.Join(dir, "user-data"), []byte(userData)); err != nil {
		return "", err
	}
	if err := engine.WritePrivate(filepath.Join(dir, "meta-data"), []byte("instance-id: "+id+"\nlocal-hostname: airgapproof\n")); err != nil {
		return "", err
	}
	iso := filepath.Join(filepath.Dir(dir), id+".iso")
	_, err := engine.Run(ctx, nil, "xorriso", "-as", "mkisofs", "-quiet", "-V", "cidata", "-J", "-r", "-o", iso, dir)
	return iso, err
}
func VMPrepare(ctx context.Context, cloudImage, output, arch, firmware string, log Options) error {
	var err error
	cloudImage, err = filepath.Abs(cloudImage)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if strings.ContainsAny(output+cloudImage, ",\n") {
		return errors.New("VM image paths cannot contain commas or newlines")
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		return errors.New("VM output must not already exist")
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	imageInfo, err := os.Stat(cloudImage)
	if err != nil {
		return err
	}
	if err = engine.RequireSpace(filepath.Dir(output), uint64(imageInfo.Size())+engine.DiskReserve); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(output), ".airgap-vm-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	disk := filepath.Join(dir, "prepared.qcow2")
	if _, err = engine.Run(ctx, nil, "qemu-img", "convert", "-O", "qcow2", cloudImage, disk); err != nil {
		return err
	}
	if _, err = engine.Run(ctx, nil, "qemu-img", "resize", disk, "12G"); err != nil {
		return err
	}
	seed := filepath.Join(dir, "seed")
	if err = os.Mkdir(seed, 0700); err != nil {
		return err
	}
	userData := cloudConfig(`apt-get update
apt-get install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
ap_arch=$(dpkg --print-architecture)
echo "deb [arch=$ap_arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
curl -fsSL "https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-$ap_arch" -o "/tmp/kind-linux-$ap_arch"
curl -fsSL "https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-$ap_arch.sha256sum" -o /tmp/kind.sha256sum
(cd /tmp && sha256sum --check kind.sha256sum)
install -m 0755 "/tmp/kind-linux-$ap_arch" /usr/local/bin/kind
rm -f "/tmp/kind-linux-$ap_arch" /tmp/kind.sha256sum
systemctl enable docker
cloud-init clean --logs --seed
echo AIRGAPPROOF_VM_PREPARED > /dev/console
sync
poweroff
`)
	iso, err := seedISO(ctx, seed, userData, "ap-prepare")
	if err != nil {
		return err
	}
	binary, args, err := QEMUArgs(disk, iso, arch, firmware, true)
	if err != nil {
		return err
	}
	if log.Log != nil {
		fmt.Fprintln(log.Log, "Provisioning a dedicated Ubuntu VM online; test runs will have no virtual NIC")
		fmt.Fprintln(log.Log, "QEMU:", strings.Join(args[:10], " "))
	}
	b, err := engine.Run(ctx, nil, binary, args...)
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte("AIRGAPPROOF_VM_PREPARED\r\n")) && !bytes.Contains(b, []byte("AIRGAPPROOF_VM_PREPARED\n")) {
		return errors.New("VM provisioning did not produce a completion marker")
	}
	if err = os.Chmod(disk, 0600); err != nil {
		return err
	}
	return os.Rename(disk, output)
}
func VMTest(ctx context.Context, c *config.Config, opts Options) (*report.Report, error) {
	arch := c.Isolation.VMArch
	if arch == "" {
		arch = runtime.GOARCH
	}
	binaryPath := c.Isolation.VMBinary
	if binaryPath == "" && runtime.GOOS == "linux" && arch == runtime.GOARCH {
		binaryPath, _ = os.Executable()
	}
	if binaryPath == "" {
		return nil, errors.New("disconnected mode requires isolation.vm_binary containing the Linux CLI for the guest architecture")
	}
	binaryPath = c.Path(binaryPath)
	dir, err := os.MkdirTemp("", "airgapproof-vm-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	seed := filepath.Join(dir, "seed")
	if err = os.Mkdir(seed, 0700); err != nil {
		return nil, err
	}
	if err = bundle.Export(ctx, c, filepath.Join(seed, "bundle")); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(seed, "airgapproof"), b, 0700); err != nil {
		return nil, err
	}
	var inputBytes uint64
	if err = filepath.WalkDir(seed, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err == nil {
			inputBytes += uint64(info.Size())
		}
		return err
	}); err != nil {
		return nil, err
	}
	if err = engine.RequireSpace(dir, 2*inputBytes+engine.DiskReserve); err != nil {
		return nil, err
	}
	userData := cloudConfig(`mkdir -p /mnt/ap-input /work
mount -o ro /dev/disk/by-label/cidata /mnt/ap-input
cp /mnt/ap-input/airgapproof /usr/local/bin/airgapproof
chmod 0755 /usr/local/bin/airgapproof
systemctl start docker
airgapproof bundle load /mnt/ap-input/bundle
airgapproof test --config /mnt/ap-input/bundle/airgapproof.yaml --report /work/report --timeout 15m || true
test -s /work/report/report.json
printf "\nAIRGAPPROOF_REPORT_BEGIN\n" > /dev/console
base64 -w0 /work/report/report.json > /dev/console
printf "\nAIRGAPPROOF_REPORT_END\n" > /dev/console
sync
poweroff
`)
	iso, err := seedISO(ctx, seed, userData, "ap-offline")
	if err != nil {
		return nil, err
	}
	base := c.Path(c.Isolation.VMImage)
	if strings.ContainsAny(base, ",\n") {
		return nil, errors.New("VM path cannot contain commas or newlines")
	}
	disk := filepath.Join(dir, "snapshot.qcow2")
	if _, err = engine.Run(ctx, nil, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", base, disk); err != nil {
		return nil, err
	}
	firmware := c.Isolation.VMFirmware
	if firmware != "" {
		firmware = c.Path(firmware)
	}
	qemu, args, err := QEMUArgs(disk, iso, arch, firmware, false)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(opts.Log, "Running disposable VM snapshot with -nic none")
	fmt.Fprintln(opts.Log, "QEMU:", strings.Join(args[:10], " "))
	out, err := engine.Run(ctx, nil, qemu, args...)
	if err != nil {
		return nil, err
	}
	begin := []byte("AIRGAPPROOF_REPORT_BEGIN\r\n")
	index := bytes.LastIndex(out, begin)
	if index < 0 {
		begin = []byte("AIRGAPPROOF_REPORT_BEGIN\n")
		index = bytes.LastIndex(out, begin)
	}
	if index < 0 {
		return nil, errors.New("disconnected VM did not return a report")
	}
	data := out[index+len(begin):]
	end := bytes.Index(data, []byte("AIRGAPPROOF_REPORT_END"))
	if end < 0 {
		return nil, errors.New("disconnected VM returned an incomplete report")
	}
	data = bytes.TrimSpace(data[:end])
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	var r report.Report
	if err = json.Unmarshal(decoded, &r); err != nil {
		return nil, err
	}
	if err = r.Validate(); err != nil {
		return nil, err
	}
	r.Isolation.Mode = "disconnected"
	r.Isolation.Checks = append(r.Isolation.Checks, "QEMU resource configuration: "+strings.Join(args[:10], " "))
	r.Isolation.Checks = append(r.Isolation.Checks, "QEMU was launched with -nic none; no virtual network card or host filesystem share was provided.", "Images and artifacts entered through a read-only ISO; execution used a disposable QCOW2 snapshot.")
	r.Gaps = append(r.Gaps, "VM guest image and QEMU are part of the trusted computing base; application-to-hypervisor exploits are outside this test profile.")
	r.Revision = opts.Revision
	r.Signature = nil
	return &r, nil
}
func cloudConfig(script string) string {
	b, _ := json.Marshal(map[string]any{"users": []string{}, "ssh_pwauth": false, "disable_root": true, "runcmd": [][]string{{"bash", "-ceu", script}}, "power_state": map[string]any{"mode": "poweroff", "timeout": 30, "condition": true}})
	return "#cloud-config\n" + string(b) + "\n"
}
