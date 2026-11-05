# GitHub and GitLab integration

Separate the explicitly online preparation job from offline application execution.
Keep reports as artifacts even when readiness fails. The CLI returns 1 for
readiness or team-policy failures and 2 for invalid input or unavailable tooling.

## GitHub Actions

A minimal job can build application images, prepare the helper, and run a defined
profile. Pin action commits and CLI versions in your production workflow.

```yaml
name: Offline readiness
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  offline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with:
          go-version: '1.27.3'
      - run: go install github.com/cenab/airgapproof/cmd/airgapproof@v0.1.0
      - name: Preload the released helper
        run: |
          curl -fLO https://github.com/cenab/airgapproof/releases/download/v0.1.0/airgapproof-helper_v0.1.0_linux_amd64.tar.gz
          curl -fLO https://github.com/cenab/airgapproof/releases/download/v0.1.0/SHA256SUMS
          sha256sum --check --ignore-missing SHA256SUMS
          docker load --input airgapproof-helper_v0.1.0_linux_amd64.tar.gz
      - run: airgapproof prepare --config airgapproof.yaml --build
      - run: airgapproof test --config airgapproof.yaml --report airgap-report
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        if: always()
        with:
          name: offline-evidence
          path: airgap-report/
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: airgap-report/report.sarif
```

Use `tracing: required` when syscall evidence is part of your release criteria.
The runner needs BPF privileges and mounted tracefs. The project's own
[CI workflow](../.github/workflows/ci.yml) includes that setup and live tests.
SARIF upload availability depends on your repository's code-scanning settings;
the readiness exit code remains the deployment gate.

For dashboard enforcement, store a team token as the `AIRGAPPROOF_TOKEN` secret
and use an internal runner that can reach your private HTTPS dashboard. Run
`airgapproof publish airgap-report/report.json --server URL` after creating the
report. Upload failures and policy failures must not be masked with `|| true`.

## GitLab CI

GitLab runners need a Linux Docker engine that permits the required isolation
and tracing operations. The following job keeps the report after a failed scan:

```yaml
offline-readiness:
  stage: test
  tags: [linux-docker]
  script:
    - airgapproof prepare --config airgapproof.yaml --build
    - airgapproof test --config airgapproof.yaml --report airgap-report
  artifacts:
    when: always
    paths:
      - airgap-report/
    reports:
      sarif: airgap-report/report.sarif
```

Install the pinned CLI and preload the helper in the runner image. GitLab SARIF
ingestion depends on your server version and enabled features. The report files
and CLI exit code work independently of security-dashboard ingestion. Consult
[GitLab's SARIF documentation](https://docs.gitlab.com/user/application_security/detect/sarif/)
and [GitHub's upload guidance](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for your platform configuration.
