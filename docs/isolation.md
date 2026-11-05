# Isolation and evidence

AirgapProof separates three questions: whether artifacts are present, whether
external access is attempted, and whether declared workflows actually succeed.
Each report records its isolation checks and coverage gaps.

## Developer sandbox

Every application network is a fresh Docker bridge with `internal` enabled,
IPv6 disabled, and gateway mode `isolated`. Docker's isolated gateway mode omits
the host bridge address. The probe checks that it has no default route and that
IPv4 and IPv6 TCP canaries cannot connect. The original deployment's external
network attachments and published ports are not used.

Application DNS is directed at a resolver inside the sandbox. Unknown names
receive NXDOMAIN without upstream forwarding. Docker service discovery still
resolves private Compose services. Applications with custom network privileges,
host namespaces, unsafe mounts, or engine sockets are rejected before startup.

Kubernetes uses the same isolated outer bridge for its disposable node. The host
executes kubectl inside that node through Docker's management channel. CoreDNS
forwards unknown names only to the sandbox resolver. Pod canaries check failed
IPv4/IPv6 connections. This boundary does not depend on NetworkPolicy support in
kind's default CNI.

These controls assume a correctly configured, trusted Docker engine and kernel.
They do not defend against kernel exploits, malicious host administrators,
concurrent manual network attachment, or every Docker networking implementation.
Use a dedicated environment and the disconnected backend for higher assurance.

## Disconnected guest

The QEMU backend boots a snapshot of a prepared guest with `-nic none`. It
provides no host filesystem share, host network proxy, or guest SSH channel.
Preloaded images, artifacts, and a Linux CLI enter through a read-only ISO.
Reports return over the VM console. The snapshot and temporary input disk are
removed after execution, and the prepared base image is retained.

Preparation is explicitly online. Application startup and workflows run in the
later no-NIC boot. QEMU, the prepared operating system, the test CLI, and the
kernel remain trusted components. Report signatures authenticate evidence
contents; they are not remote or hardware attestation.

## Runtime tracing

The privileged Linux helper attaches eBPF programs to syscall tracepoints for
`connect` and `sendto`, with exit hooks for return codes. It records destinations
even when routing immediately denies a connection. Events are filtered to
explicit target containers and attributed using cgroup and process information.
Unrelated host workload events are not included in reports.

`connect` can represent TCP or connected UDP; the report deliberately calls it a
connection syscall rather than inferring a protocol from incomplete evidence.
A return code of `-EINPROGRESS` is an asynchronous attempt, not proof of either
connection success or functional dependence. DNS observations identify queries
and denial, not packet contents or successful downloads.

Instrumentation needs Linux tracefs, BPF support, syscall tracepoints, compatible
cgroup information, and permission to load tracing programs. Tracing failures
fail `required` profiles and produce explicit gaps in `auto` profiles. The
application itself never receives the tracer's privileges.

## Coverage limits

Reports identify limits that matter when interpreting a pass:

- Unexercised operations, scheduled jobs, and delayed outbound behavior remain
  untested.
- `sendmsg`, io_uring networking, inherited connections, raw packet mechanisms,
  and other uninstrumented paths are not comprehensive runtime coverage.
- Short-lived processes can exit before attribution completes. Tracer loss and
  bounded collection limits appear as gaps.
- DNS evidence lacks process IDs. Kubernetes forwarded DNS identifies the
  cluster resolver rather than the original pod process.
- The static scanner uses bounded heuristics, not complete language or binary
  analysis. It skips symlinks, oversized files, and common dependency directories.
- Current tracing limits are 30,000 syscall observations and 10,000 DNS queries.
  Application logs and HTTP response bodies are omitted.
- GPU behavior, multi-node failover, arbitrary operators, and production
  authentication arrangements need their own supported profiles and scenarios.

Docker documents the distinction between
[internal and isolated bridge gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).
Kubernetes documents that
[NetworkPolicy requires an enforcing network plugin](https://kubernetes.io/docs/concepts/services-networking/network-policies/).
