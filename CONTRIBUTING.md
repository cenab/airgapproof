# Contributing

Keep changes focused on a documented offline testing behavior. Include a failing
case and a passing case for isolation, artifact, scenario, or policy changes.

Run the relevant checks before submitting a change:

```sh
make check
make demo
make integration
```

Docker-dependent checks need the images prepared by `make demo-prepare`.
Kubernetes changes also need the example in `examples/kubernetes`. VM changes
need a real no-NIC guest test; a command-construction unit test alone doesn't
validate a disconnected execution backend.

Describe the problem, resulting behavior, compatibility effects, and exact
validation. Report unavailable checks and coverage gaps. Never change a readiness
result to hide a failed workflow, incomplete instrumentation, or cleanup error.
Avoid new dependencies when a standard library or existing project helper fits.
