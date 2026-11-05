package run

import (
	"strings"
	"testing"
)

func TestDisconnectedVMHasNoNICOrHostShare(t *testing.T) {
	_, args, err := QEMUArgs("/tmp/disk.qcow2", "/tmp/input.iso", "amd64", "", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-smp 4 -m 4096") {
		t.Fatal("nested Kubernetes VM resource allocation missing:", joined)
	}
	if !strings.Contains(joined, "-nic none") || strings.Contains(joined, "user,model") || strings.Contains(joined, "virtfs") || strings.Contains(joined, "9p") {
		t.Fatal(joined)
	}
	_, args, err = QEMUArgs("/tmp/disk.qcow2", "/tmp/input.iso", "amd64", "", true)
	if err != nil || !strings.Contains(strings.Join(args, " "), "-nic user,") {
		t.Fatal("online provisioning network missing")
	}
	if _, _, err = QEMUArgs("a", "b", "arm64", "", false); err == nil {
		t.Fatal("missing firmware accepted")
	}
}

func TestOfflineEvidenceDoesNotShareTheSystemConsole(t *testing.T) {
	_, args, err := QEMUArgs("/tmp/disk.qcow2", "/tmp/input.iso", "amd64", "", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"-serial null", "-chardev stdio,id=ap-report,signal=off", "-device virtio-serial-pci", "virtserialport,chardev=ap-report,name=org.airgapproof.report"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing dedicated evidence channel: %s", required)
		}
	}
}
