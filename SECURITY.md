# Security model and reports

AirgapProof tests trusted application deployments. It is not a security boundary
for adversarial code. The developer sandbox shares the Docker host kernel, and
the eBPF tracer requires privileged access. Use a dedicated host or the
disconnected VM backend for sensitive validation.

Never place production credentials in the demonstration. Reports omit application
stdout, stderr, HTTP bodies, and environment values. DNS names, process names,
image references, source locations, and explicit application identifiers can still
be sensitive. Bundles include expanded configuration and may contain secrets.

Keep signing keys outside the repository. Deploy the dashboard behind HTTPS,
restrict PostgreSQL to its private network, protect backups, and use distinct
team tokens. The dashboard has token authentication and team isolation; it does
not implement SSO, billing, hardware attestation, or a managed hosting service.

For a vulnerability, use GitHub's private vulnerability reporting on this
repository when available. Do not include secrets or exploit payloads in public
issues. See [the isolation model](docs/isolation.md) for protocol and coverage
limits relevant to interpreting a report.
