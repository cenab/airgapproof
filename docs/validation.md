# Validation record

This document records executed validation for the initial preview. Commands that
only construct a backend invocation do not count as live backend tests.

## Local execution

The initial implementation was exercised on macOS arm64 with Docker Desktop
4.92.0, Docker Engine 29.8.0, Compose 5.5.1, kind 0.33.0, QEMU 11.1.3, and an
Ubuntu 24.04 arm64 guest. Final command results are recorded below.

| Check | Observed result |
| --- | --- |
| Go unit suite | Passed |
| Compose packaged AI demo | Ready, 4/4 workflows: health, inference with PostgreSQL/Redis, exec, and restart recovery |
| Compose remote-model variant | Not ready; inference and API workflows fail while Redis remains operational |
| Required eBPF integration | Passed; a blocked `1.1.1.1:443` attempt has application container, PID, process, and negative syscall result |
| DNS attribution after restart | Passed; model-host queries remain attributed to the inference service |
| Disconnected VM smoke | Ready, with no virtual NIC and required eBPF tracing |
| Full AI application in disconnected VM | Ready, 4/4 workflows |
| Kubernetes example | Ready, 3/3 workflows: HTTP, exec, and rollout recovery |
| Kubernetes inside a disconnected VM | Ready, 3/3 workflows with required tracing and no virtual NIC |
| PostgreSQL dashboard integration | Passed: persistent reports, team isolation, authentication, token rotation, and CSRF rejection |
| Signed report verification | Passed against an explicitly trusted public key |
| Proposed Dockerfile patch | Accepted by `git apply --check` |
| Race detector, vet, workflow lint, and vulnerability scan | Passed; govulncheck found no known reachable vulnerabilities |
| Live CLI dashboard publication | Accepted signed evidence returns 0; VM-only policy rejection returns 1 |

The live sandbox test reproduced a Docker local-log-driver startup error before
the log-rotation setting was corrected. A regression test also reproduced local
unspecified sockets being classified as external before the shared address
classification was fixed. The AI application provides both a demonstrated
offline failure and a demonstrated self-contained pass.

A real child-process regression also reproduced command diagnostics exceeding
their byte limit through an embedded buffer's streaming method. The shared
command runner now retains only the bounded output, and the regression passes.

A digest-pinned kind image reproduced an offline image-identity lookup failure
after Docker save/load. The regression test failed before the fix and passed
afterward. Bundles now create content-derived local aliases, verify their image
identities, and use those aliases for both Compose and Kubernetes. The combined
no-NIC Kubernetes run also exercises this path with an actual image import.

The first combined Linux VM job passed its Compose smoke but failed kind startup
before running Kubernetes workflows. That failure remains recorded in
[its workflow run](https://github.com/cenab/airgapproof/actions/runs/41999957475).
The VM allocation was raised from two vCPUs/2 GiB to four vCPUs/4 GiB, and CI
checks available KVM access. Bootstrap diagnostics and the selected accelerator
are recorded for interpreting subsequent runs.

The resource recheck passed the VM smoke, but its Kubernetes bootstrap still
timed out. Its evidence showed KVM during preparation and software emulation
during both test boots. CI now starts the entire VM sequence with the runner's
`kvm` group and asserts that hardware acceleration remains active when provided.
This replaces the one-time device ACL used by the failed run. The
[following VM job](https://github.com/cenab/airgapproof/actions/runs/42007844587/job/127179266160)
passed smoke (1/1) and nested Kubernetes (3/3), with KVM retained across
preparation and both test boots. Both offline runs verified isolation and
required tracing.

A subsequent CI smoke failed while decoding evidence from the shared system
console. Offline boots now return JSON over a dedicated virtio serial port;
system-console output is excluded from that channel. The no-NIC and no-host-share
boundary is preserved.

A subsequent local resource recheck was cancelled when the host ran low on disk;
it is not counted as a passing run. Temporary test files were cleared. Export and
VM execution now check estimated disk requirements with a host reserve, and the
guest no longer duplicates the input image archive onto its writable disk.

## Reproduce the checks

Use these commands from a clean checkout with Docker available:

```sh
make check
make demo
AIRGAPPROOF_INTEGRATION=1 AIRGAPPROOF_REQUIRE_TRACING=1 \
  go test -v ./internal/run ./internal/dashboard -timeout 8m
bin/airgapproof prepare --config examples/kubernetes/airgapproof.yaml
bin/airgapproof test --config examples/kubernetes/airgapproof.yaml \
  --report reports/kubernetes --timeout 8m
sh scripts/check-vm.sh
```

The GitHub workflow also tests Linux amd64, a separately provisioned Ubuntu VM,
Kubernetes in that VM, artifact export/load/re-execution, and signed evidence.
The [first full CI run](https://github.com/cenab/airgapproof/actions/runs/41997277802)
passed all four jobs. Inspect the
[repository's workflow runs](https://github.com/cenab/airgapproof/actions) for
the exact commit and completed job results.

## Unavailable and untested coverage

Interactive browser visual inspection was unavailable because local browser use
is disabled in the workspace settings. HTTP rendering and authentication paths
are tested; screen-reader and manual visual review are not claimed.

The project has not been evaluated against arbitrary production applications,
GPU hardware, Windows containers, multi-node recovery, third-party Kubernetes
operators, enterprise SSO, or hardware attestation. GitLab configuration is a
documented integration example, not a live GitLab server validation. Current
protocol and instrumentation limits are listed in [the isolation model](isolation.md).
