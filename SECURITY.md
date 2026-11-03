# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" form on this
repository (Security → Advisories → Report a vulnerability). Do not open a public issue.

Include: affected component (agent, processor, detect, api, web, deploy), version or commit,
reproduction steps, and impact. You will receive an acknowledgement within 3 business days and a
remediation plan or status update within 10 business days. We follow a 90-day coordinated
disclosure window, shortened when a fix ships earlier.

## Supported versions

| Version | Supported |
|---|---|
| `main` | yes |
| latest tagged minor | yes, security fixes |
| older | no |

## Security design

The threat model, trust boundaries and the mitigation for each threat (with code locations) are
in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Hardening guidance for operators is in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Controls applied to this repository

- Semgrep, gosec and Bandit static analysis on every pull request; CI fails on HIGH/CRITICAL.
- `govulncheck`, `npm audit`, `pip-audit` and Trivy (filesystem and image) dependency scanning.
- gitleaks secret scanning on every push.
- Parser fuzzing (`go test -fuzz`) with committed corpora.
- CycloneDX SBOM generated for every image; images signed with cosign (keyless, Sigstore).
- Branch protection with required reviews and status checks on `main`.

## Secrets

Argus never logs secrets (see `internal/telemetry/log/redact.go` and the log scan test). Secrets
are provided by environment variables or mounted files; see `deploy/helm/argus/values.yaml` and
`deploy/terraform/aws/secrets.tf` for the supported injection paths.
