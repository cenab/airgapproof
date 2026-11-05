# Configuration and compatibility

Profiles use schema version `1`. Unknown fields, multiple YAML documents, duplicate
scenario names, unsupported isolation modes, and invalid recovery references fail
before application startup. Paths resolve relative to the profile, except the
explicit `--compose` flag, which resolves relative to your working directory.

## Profile fields

Choose exactly one deployment backend in `application`:

| Field | Meaning |
| --- | --- |
| `application.name` | Application label shown in reports |
| `application.compose` | A self-contained Compose file |
| `application.kubernetes` | List of local, rendered Kubernetes manifest files |
| `application.node_image` | Preloaded kind node image, pinned by default |
| `isolation.mode` | `developer` or `disconnected` |
| `isolation.tracing` | `auto`, `required`, or `off` |
| `isolation.fail_on_attempts` | Fail observed external attempts; requires tracing |
| `artifacts.helper_image` | Preloaded Linux helper image reference |
| `artifacts.files` | Required local files to checksum and include in bundles |
| `report.formats` | `json`, `html`, and/or `sarif`; JSON is always written by `test` |

`deny_external_network`, `allow_internal_services`, and
`require_preloaded_images` can be omitted or set to `true`. Setting them to
`false` is rejected. There is no online fallback in a test run.

## Functional scenarios

Each scenario needs a unique `name`, a `type`, and an optional duration such as
`timeout: 45s`. The default is 30 seconds; the maximum is 30 minutes. The CLI's
overall `--timeout` also bounds startup and all scenarios together.

| Type | Fields and behavior |
| --- | --- |
| `http` | `url`, `expected_status` (default 200), `expected_contains`, optional `method`, `headers`, and `body` |
| `exec` | `service`, argv-style `command`, and `expected_exit_code` (default 0) |
| `restart` | `service` and `verify`, which names an HTTP or exec scenario |

HTTP requests ignore proxy environment variables, retain TLS certificate
validation, and do not follow redirects. Responses over 1 MiB cannot satisfy the
body assertion. GET and HEAD retry for startup readiness; POST and other methods
run once to avoid repeating writes. Exec commands also run once. An HTTP status
match alone does not validate application semantics; add response assertions or
use an application-owned workflow script.

Compose exec targets are service names. Kubernetes exec targets can be
`deployment/name`, `statefulset/name`, or `pod/name`; a bare name means a
Deployment. Recovery supports Deployments and StatefulSets and verifies the
rollout before rerunning the referenced scenario.

## Supported Compose deployments

AirgapProof uses the official Compose configuration model for interpolation and
normalization. It preserves service commands, environment, health checks,
dependencies, private network membership, aliases, and supported storage.

Supported deployments have these properties:

- Linux images are built and present in the selected Docker engine.
- Each service has an explicit image and one replica.
- Networks use the bridge driver without external attachments or custom IPAM.
- Writable application state uses new run-owned named volumes or tmpfs.
- Host file mounts are read-only regular files or directories inside the profile
  directory, without sockets, devices, or nested symlinks.
- Configs and secrets come from local files or supported inline Compose values.

Host networking, host namespaces, elevated privileges, added capabilities,
devices, external links, Docker sockets, external volumes, lifecycle hooks,
providers, custom security profiles, remote logging drivers, `include`, and
`extends` are rejected. Flatten Compose includes and extensions before testing.
Unsupported settings fail closed rather than being silently ignored.

The test copy removes published host ports, build configuration, fixed container
names, and restart policies. It gives services stable sandbox addresses so
restart-related address reuse cannot corrupt DNS attribution. Named volumes get
random run-owned names. These differences are part of the recorded test profile;
the original Compose file and production volumes are never changed.

Only active default-profile services are tested. Compose profiles, multiple
replicas, arbitrary bind-writable development environments, and Windows
containers are outside the current compatibility set.

## Supported Kubernetes deployments

The backend accepts Pods, Deployments, StatefulSets, Jobs, Services, ConfigMaps,
Secrets, PersistentVolumeClaims, and NetworkPolicies in their standard API
versions. Lists are flattened. All objects enter a fresh namespace in a fresh
single-node kind cluster.

Workload images, including init containers, are preloaded and rewritten to
`imagePullPolicy: Never`. Host networking, host namespaces, host ports, hostPath
and external storage sources, external services, custom DNS, elevated
capabilities, and privilege escalation are rejected. Service account token
automounting is disabled. Workload images must support these restrictions.

CRDs, operators, cluster-scoped resources, webhooks, external secrets, ingress
controllers, LoadBalancer and NodePort services, and arbitrary annotations are
unsupported. Render Helm charts locally before testing. Additional images used
implicitly by storage provisioners or other controllers are not discovered
automatically; their absence can make a workflow fail.

## Exit codes and output

CI can gate on a stable exit-code contract:

| Code | Meaning |
| --- | --- |
| `0` | Defined workflows and required checks passed, or the requested utility command succeeded |
| `1` | Offline readiness or organizational policy did not pass |
| `2` | Invalid input, unavailable tooling, or a utility/preflight execution error |

A failed execution after report creation produces a non-ready JSON report.
Errors before a report can be constructed return code 2. Report writes are
atomic and use private file permissions. Application output, HTTP bodies, and
environment values are not included. Keep DNS, process, image, and path evidence
private when it can reveal internal system information.
