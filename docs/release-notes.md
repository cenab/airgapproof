AirgapProof's first preview provides a Go developer CLI, isolated Compose runs,
functional and recovery scenarios, static dependency discovery, Linux eBPF
connection tracing, JSON/HTML/SARIF reports, checksummed offline artifact bundles,
disposable no-NIC QEMU execution, and a kind-based Kubernetes backend.

The private PostgreSQL dashboard adds team tokens, saved organizational policy
decisions, release comparisons, and trusted Ed25519 evidence verification.

Downloads include CLI archives for macOS and Linux on amd64 and arm64, plus
Linux helper and dashboard container archives for offline loading. Verify the
archives with `SHA256SUMS`; container downloads don't require a registry account.

Start with `make demo` to compare a working packaged AI model against the same
application with a startup download dependency. Read the compatibility and
isolation documentation before applying readiness results to a release.

This is a preview. A pass covers the recorded images, profile, and workflows.
Unsupported protocols, untested workflows, and instrumentation gaps are explicit
in reports. SSO, managed hosting, hardware attestation, and arbitrary Kubernetes
operators are outside this release.
