#!/bin/sh
set -eu

ap_tmp=$(mktemp -d)
trap 'rm -rf "$ap_tmp"' EXIT HUP INT TERM
ap_root=$(pwd)
ap_firmware=${AIRGAPPROOF_VM_FIRMWARE:-}
case $(uname -m) in
  x86_64) ap_arch=amd64 ;;
  arm64|aarch64)
    ap_arch=arm64
    if [ -z "$ap_firmware" ]; then
      ap_prefix=$(dirname "$(dirname "$(command -v qemu-system-aarch64)")")
      ap_firmware="$ap_prefix/share/qemu/edk2-aarch64-code.fd"
    fi
    ;;
  *) echo 'Unsupported VM host architecture' >&2; exit 2 ;;
esac

ap_base=${AIRGAPPROOF_VM_IMAGE:-}
if [ -z "$ap_base" ]; then
  ap_cloud="noble-server-cloudimg-$ap_arch.img"
  curl -fsSL "https://cloud-images.ubuntu.com/noble/current/$ap_cloud" -o "$ap_tmp/$ap_cloud"
  curl -fsSL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS -o "$ap_tmp/SHA256SUMS"
  python3 - "$ap_tmp/$ap_cloud" "$ap_tmp/SHA256SUMS" <<'PY'
import hashlib
import pathlib
import sys
image, manifest = map(pathlib.Path, sys.argv[1:])
expected = next(line.split()[0] for line in manifest.read_text().splitlines()
                if line.split()[-1].lstrip('*') == image.name)
with image.open('rb') as stream:
    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
assert actual == expected, 'Ubuntu cloud image checksum mismatch'
PY
  ap_base="$ap_tmp/prepared.qcow2"
  if [ -n "$ap_firmware" ]; then
    bin/airgapproof vm prepare --cloud-image "$ap_tmp/$ap_cloud" --output "$ap_base" --arch "$ap_arch" --firmware "$ap_firmware"
  else
    bin/airgapproof vm prepare --cloud-image "$ap_tmp/$ap_cloud" --output "$ap_base" --arch "$ap_arch"
  fi
  rm "$ap_tmp/$ap_cloud"
fi

CGO_ENABLED=0 GOOS=linux GOARCH="$ap_arch" go build -o "$ap_tmp/airgapproof-linux" ./cmd/airgapproof
cat > "$ap_tmp/compose.yaml" <<'EOF'
services:
  web:
    image: nginx:1.28-alpine
EOF
python3 - "$ap_tmp" "$ap_base" "$ap_arch" "$ap_firmware" <<'PY'
import json
import pathlib
import sys
root, image, arch, firmware = sys.argv[1:]
profile = {'version': 1, 'application': {'name': 'Disconnected VM smoke', 'compose': 'compose.yaml'},
           'isolation': {'mode': 'disconnected', 'tracing': 'required', 'vm_image': image,
                         'vm_arch': arch, 'vm_binary': root + '/airgapproof-linux'},
           'scenarios': [{'name': 'web', 'type': 'http', 'url': 'http://web/',
                          'expected_status': 200, 'expected_contains': 'Welcome to nginx', 'timeout': '30s'}]}
if firmware:
    profile['isolation']['vm_firmware'] = firmware
pathlib.Path(root, 'airgapproof.yaml').write_text(json.dumps(profile))
PY
bin/airgapproof prepare --config "$ap_tmp/airgapproof.yaml"
bin/airgapproof test --config "$ap_tmp/airgapproof.yaml" --report "$ap_root/reports/vm-smoke" --timeout 20m
python3 - "$ap_root/reports/vm-smoke/report.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    report = json.load(stream)
assert report['status'] == 'ready'
assert report['isolation']['mode'] == 'disconnected'
assert report['isolation']['verified'] and report['isolation']['tracing']
assert any('-nic none' in check for check in report['isolation']['checks'])
print('Verified disconnected guest workflows and required runtime tracing.')
PY

python3 - "$ap_tmp" "$ap_base" "$ap_arch" "$ap_firmware" "$ap_root" <<'PY'
import json
import pathlib
import sys
root, image, arch, firmware, repository = sys.argv[1:]
profile = {'version': 1,
           'application': {'name': 'Disconnected Kubernetes', 'kubernetes': [repository + '/examples/kubernetes/app.yaml']},
           'isolation': {'mode': 'disconnected', 'tracing': 'required', 'vm_image': image,
                         'vm_arch': arch, 'vm_binary': root + '/airgapproof-linux'},
           'scenarios': [{'name': 'web', 'type': 'http', 'url': 'http://web/',
                          'expected_status': 200, 'expected_contains': 'Welcome to nginx', 'timeout': '60s'},
                         {'name': 'configuration', 'type': 'exec', 'service': 'deployment/web',
                          'command': ['nginx', '-t'], 'expected_exit_code': 0},
                         {'name': 'recovery', 'type': 'restart', 'service': 'deployment/web',
                          'verify': 'web', 'timeout': '60s'}]}
if firmware:
    profile['isolation']['vm_firmware'] = firmware
pathlib.Path(root, 'kubernetes-profile.yaml').write_text(json.dumps(profile))
PY
bin/airgapproof prepare --config "$ap_tmp/kubernetes-profile.yaml"
bin/airgapproof test --config "$ap_tmp/kubernetes-profile.yaml" --report "$ap_root/reports/vm-kubernetes" --timeout 20m
python3 - "$ap_root/reports/vm-kubernetes/report.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    report = json.load(stream)
assert report['status'] == 'ready' and len(report['scenarios']) == 3
assert report['isolation']['mode'] == 'disconnected'
assert report['isolation']['backend'] == 'kubernetes'
assert report['isolation']['verified'] and report['isolation']['tracing']
print('Verified Kubernetes HTTP, exec, and rollout recovery inside a disconnected guest.')
PY
