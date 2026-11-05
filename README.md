# AirgapProof

Test whether your application's required workflows work without internet access.
AirgapProof discovers potential dependencies, runs preloaded applications in an
isolated environment, captures network attempts, and produces evidence you can
use in CI and release reviews.

> **Note:** This is a preview feature currently under active development.

The repository includes working implementations across all four project phases:
the Compose CLI, dependency discovery and Linux tracing, disconnected VMs and
Kubernetes, and a private evidence dashboard. A passing result applies to the
images, profile, and scenarios recorded in that report. It does not prove every
possible application behavior works offline.

## Run the demonstration

You need Go 1.27+, Docker Engine 28+, and Docker Compose v2 or newer. Docker
Desktop with Linux containers works on macOS. Build and preparation steps use the
internet; `test` never builds or pulls application images.

```sh
git clone https://github.com/cenab/airgapproof.git
cd airgapproof
make demo
```

The demo runs FastAPI, PostgreSQL, Redis, and a local ONNX sentence embedding
model from Hugging Face. It verifies inference, database persistence, caching,
and recovery after restarting the API. The packaged-model variant passes; the
variant that needs to download model files fails offline.

Open `reports/offline/report.html` and `reports/remote/report.html` to compare
the evidence. See [the demo's model and dependencies](examples/ai-app/README.md).

## Test your application

Build the CLI and helper, then prepare your application's images while online.
You don't need to change application source code for a supported deployment.

```sh
make build helper
bin/airgapproof prepare --compose docker-compose.yml --config airgapproof.yaml --build
bin/airgapproof test \
  --compose docker-compose.yml \
  --config airgapproof.yaml \
  --report ./airgap-report \
  --revision release-2026-11
```

Use a profile that describes actual operations, rather than startup alone:

```yaml
version: 1
application:
  name: Customer application
  compose: docker-compose.yml
isolation:
  mode: developer
  tracing: auto
  fail_on_attempts: false
artifacts:
  require_preloaded_images: true
scenarios:
  - name: health
    type: http
    url: http://api:8080/health
    expected_status: 200
    timeout: 30s
  - name: operation
    type: exec
    service: api
    command: [python, /tests/offline_workflow.py]
    expected_exit_code: 0
  - name: recovery
    type: restart
    service: api
    verify: health
report:
  formats: [json, html, sarif]
```

HTTP probes run inside the application network, so private service names work
without publishing host ports. GET and HEAD probes retry until their deadline;
other HTTP methods and exec commands run once. Redirects are not followed.
Response assertions use `expected_contains`. Request bodies and application
output are omitted from reports; HTTP results include a response digest.

Unknown profile fields are errors. Image pulls cannot be enabled in a test.
See [configuration and compatibility](docs/configuration.md) for supported
Compose settings, Kubernetes resources, and exit codes.

## Choose an isolation profile

The two execution levels serve different assurance requirements:

| Profile | Mechanism | Intended use |
| --- | --- | --- |
| Developer | Internal Docker bridges with isolated gateway mode, private DNS, preflight rejection, and connectivity checks | Local feedback and CI |
| Disconnected | Disposable QEMU guest with `-nic none`, a read-only input ISO, and a snapshot disk | Tests without any guest network interface to the outside |

Linux eBPF tracing records `connect` and `sendto` calls, including failed attempts,
with container, PID, process, destination, port, and syscall return code. DNS
queries receive NXDOMAIN without upstream forwarding. `tracing: required` fails
if instrumentation cannot attach; `auto` records a coverage gap when unavailable.
`fail_on_attempts: true` requires tracing and makes observed external attempts
fail the run. Optional telemetry attempts otherwise remain warnings when the
defined workflows pass.

Applications must be trusted workloads. The developer sandbox shares a kernel
with Docker; its tracing helper needs elevated Linux privileges. Read the exact
[isolation model and coverage limits](docs/isolation.md). For the VM workflow,
see [disconnected execution](docs/disconnected.md).

## Test Kubernetes manifests

AirgapProof creates a disposable single-node kind cluster, loads local images,
validates and hardens supported workloads, and runs HTTP, exec, and rollout
recovery scenarios. Install kind v0.33.0 before running this example:

```sh
bin/airgapproof prepare --config examples/kubernetes/airgapproof.yaml
bin/airgapproof test --config examples/kubernetes/airgapproof.yaml \
  --report reports/kubernetes --timeout 8m
```

The cluster's outer Docker network enforces isolation. AirgapProof does not claim
that kind's default CNI enforces Kubernetes NetworkPolicy. Helm charts must be
rendered to local manifests first; remote operators and admission webhooks are
rejected. The host controls the cluster through Docker exec rather than an
externally published API port.

## Export offline artifacts

Bundles contain deployment configuration, declared files and read-only mounts,
Docker images, image identities, and a SHA-256 file manifest. Export requires
preloaded images and creates a new directory:

```sh
bin/airgapproof bundle export --config examples/ai-app/airgapproof.yaml \
  --output dist/offline-bundle
bin/airgapproof bundle verify dist/offline-bundle
bin/airgapproof bundle load dist/offline-bundle
bin/airgapproof test --config dist/offline-bundle/airgapproof.yaml
```

Verification rejects changed files, unlisted files, duplicate paths, traversal,
and symlinks. Checksums establish bundle integrity relative to its manifest;
they do not authenticate the manifest's publisher. Bundles can contain expanded
configuration and secrets. Keep the bundle directory private and transfer it
through your approved artifact process.

## Inspect dependencies and propose a fix

Static results identify potential dependencies and never establish functional
dependence on their own. Scanning is bounded and does not follow symlinks:

```sh
bin/airgapproof scan ./application --output dependencies.json
bin/airgapproof patch-model --dockerfile Dockerfile \
  --model models/my-approved-model --output package-model.patch
```

`patch-model` produces a proposed Dockerfile diff. It does not download model
artifacts, apply patches, select a license, or guess your application's model
configuration. Review the artifact and build context, configure the application
to load the copied local model, rebuild, and rerun the required workflows.

## Sign evidence and apply team policies

The dashboard stores run history in PostgreSQL, separates teams with scoped
tokens, evaluates organizational policies, and compares releases. It can require
disconnected execution, runtime tracing, workflow counts, warning limits, and
signatures from trusted Ed25519 keys.

```sh
bin/airgapproof keygen --output evidence.key
bin/airgapproof test --config airgapproof.yaml \
  --report airgap-report --sign-key evidence.key
bin/airgapproof verify airgap-report/report.json --public-key evidence.key.pub
bin/airgapproof publish airgap-report/report.json \
  --server https://airgapproof.example.internal
```

`publish` reads the team token from `AIRGAPPROOF_TOKEN` and returns a nonzero
exit status when the stored report fails team policy. Keys authenticate report
contents and the signer; they do not provide hardware attestation.

Follow [private dashboard deployment and API usage](docs/dashboard.md) and the
[GitHub and GitLab examples](docs/ci.md). The dashboard uses no external assets,
analytics, or browser API calls to public services.

## Develop and validate

The repository includes unit tests for configuration, isolation rejection,
signatures, policy gates, DNS, HTTP behavior, artifact tampering, and safe writes.
Live tests exercise the AI demo and PostgreSQL dashboard:

```sh
make check
make demo-prepare
make integration
```

See [validation results](docs/validation.md) for executed checks and limitations,
and [contributing](CONTRIBUTING.md) for changes to supported behavior.
