# Disconnected VM execution

The disconnected backend uses QEMU, `qemu-img`, and `xorriso`. Prepare a trusted
Ubuntu cloud image online, preload application artifacts in Docker, then execute
a separate boot with no virtual network interface.

## Prepare the guest

Install the platform tools using your package manager. On macOS:

```sh
brew install qemu xorriso
make build
mkdir -p .work
```

Obtain the appropriate Ubuntu cloud image and its checksum manifest from
[Ubuntu's official image directory](https://cloud-images.ubuntu.com/noble/current/).
For an Apple Silicon host:

```sh
curl -fL https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img \
  -o .work/noble-server-cloudimg-arm64.img
curl -fL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS \
  -o .work/SHA256SUMS
(cd .work && rg 'noble-server-cloudimg-arm64.img$' SHA256SUMS | shasum -a 256 -c)
bin/airgapproof vm prepare \
  --cloud-image .work/noble-server-cloudimg-arm64.img \
  --output .work/prepared-arm64.qcow2 \
  --arch arm64 \
  --firmware /opt/homebrew/share/qemu/edk2-aarch64-code.fd
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o bin/airgapproof-linux-arm64 ./cmd/airgapproof
```

The image must have functioning cloud-init support. Preparation installs Docker,
Compose, and a checksummed kind binary from official distribution sources. It
doesn't put application artifacts into the reusable base disk. Output must be a
new path, so an existing base image cannot be overwritten accidentally.

For Linux amd64, use the `amd64` Ubuntu image and `--arch amd64`; the default BIOS
boot does not require an explicit firmware file. A native Linux CLI can reuse
its own executable in the guest. QEMU uses KVM or Apple's Hypervisor Framework
when available for the host architecture, otherwise software emulation.

## Run the offline application

Set the following fields in a copy of your application's test profile:

```yaml
isolation:
  mode: disconnected
  tracing: required
  vm_image: /absolute/path/to/prepared-arm64.qcow2
  vm_arch: arm64
  vm_firmware: /opt/homebrew/share/qemu/edk2-aarch64-code.fd
  vm_binary: /absolute/path/to/airgapproof-linux-arm64
```

Preload images on the host with `prepare` or `bundle load`, then run:

```sh
bin/airgapproof test --config airgapproof.yaml \
  --report reports/disconnected --timeout 20m
```

The CLI exports a checksummed bundle, copies it and the Linux executable into a
read-only ISO, creates a QCOW2 snapshot, and launches QEMU with `-nic none`.
Inside the guest, the CLI verifies and loads the bundle before running the same
Compose or Kubernetes workflows. Reports record both inner sandbox checks and
the outer no-NIC boundary. The host's original deployment and base disk are
preserved.

Allow enough disk space for the prepared guest, image archive, input ISO, and
temporary snapshot. GPU passthrough, cross-architecture application emulation,
Windows guests, and hypervisor exploit resistance are outside the tested profile.
