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
| PostgreSQL dashboard integration | Passed: persistent reports, team isolation, authentication, token rotation, and CSRF rejection |
| Signed report verification | Passed against an explicitly trusted public key |
| Proposed Dockerfile patch | Accepted by `git apply --check` |

The live sandbox test reproduced a Docker local-log-driver startup error before
the log-rotation setting was corrected. A regression test also reproduced local
unspecified sockets being classified as external before the shared address
classification was fixed. The AI application provides both a demonstrated
offline failure and a demonstrated self-contained pass.

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
artifact export/load/re-execution, and signed evidence. Inspect the
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
