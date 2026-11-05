# Implementation and acceptance plan

AirgapProof verifies a defined application's workflows against a recorded offline
profile. It never treats a successful launch as proof of complete offline support.

The implementation reaches the CLI, strict configuration parser, Compose and
Kubernetes adapters, Linux helper, artifact bundles, disconnected QEMU backend,
report formats, signing tools, PostgreSQL dashboard, CI integrations, examples,
tests, and documentation. Existing applications are never changed in place.

1. Implement strict configuration and evidence schemas. Reject unknown or unsafe
   settings before creating application resources. Test isolation rejection cases.
2. Implement an isolated Compose project with preloaded images, private DNS,
   HTTP, exec, and recovery scenarios, bounded evidence, and cleanup on failure.
   Verify a self-contained demo passes and its remote-model variant fails.
3. Add static dependency findings and optional Linux eBPF syscall tracing with
   container/process attribution. Record tracing gaps and dropped events.
4. Export and validate checksummed image/artifact bundles. Provision a QEMU guest
   separately, then run disposable snapshot tests with no virtual NIC.
5. Implement a disposable kind cluster on an isolated network, local image loading,
   safe manifest validation, private DNS, workflows, and recovery checks.
6. Implement report signing and verification, a private PostgreSQL-backed dashboard,
   team tokens, policy evaluation, release comparisons, and CI examples.
7. Run unit, integration, security, CLI, and backend checks. Publish the repository,
   follow GitHub Actions to completion, and record actual validation and limitations.

Safety boundaries: runs use random resource names and labels; cleanup removes only
run-owned containers, networks, and volumes. External volumes, writable host binds,
engine sockets, host namespaces, elevated application privileges, and unsupported
network attachments are rejected. Reports omit environment values and application
output by default. Applications remain trusted workloads, not hostile-code sandboxes.

Each phase has executable code and a documented test path. A backend or tracer that
cannot execute must return a failure or an explicit coverage gap, never a fabricated
successful result. Public documentation distinguishes implemented behavior from
validation performed on this machine and in CI.
