# Security Standards

This project is built with secure-by-default behavior and explicit release gates.

## Secure Coding Baseline

- Keep `Set-StrictMode -Version Latest` and `$ErrorActionPreference = "Stop"` in security-sensitive scripts.
- Prefer explicit allow-lists over broad trust decisions (URLs, owners/repos, file paths, schema keys).
- Avoid `Invoke-Expression` in runtime paths.
- Avoid `ExecutionPolicy Bypass` for normal launch/install flows.
- Validate all downloaded content with integrity checks before execution/use.
- Keep secrets and private keys out of the repository.
- Write security-relevant events to logs with clear context.

## Installer and Update Controls

- QuickSetup validates trusted source URLs and per-file SHA-256 hashes from `QuickSetup.manifest.json`.
- Detached manifest signatures (`QuickSetup.manifest.sig`) are required and verified with RSA/SHA-256.
- Update checks enforce trusted owner/repo URL validation and can require hash/signature verification.
- Script signature enforcement is supported via `RequireScriptSignature` and trusted signer thumbprints.

## CI Quality Gates

- Parse verification (`Tools/ci/Verify.ps1`)
- Privacy/security leak scanning (`Tools/ci/Find-PrivacyLeaks.ps1`)
- PSScriptAnalyzer warnings bounded by `Tools/config/PSScriptAnalyzer.warning-budget.json`
- Pester tests with coverage gate from `Tools/config/Pester.coverage.json`
- QuickSetup manifest freshness + signature check (`Tools/release/Generate-QuickSetupManifest.ps1 -Check -RequireSignature`)
- Automated tag-based release signing and publishing (`.github/workflows/release.yml`)

## Branch Protection Baseline (GitHub)

Recommended settings for `main`:

- Require pull request before merging.
- Require status checks to pass before merging.
- Require branch to be up to date before merging.
- Require conversation resolution before merging.
- Include administrators in protection.
- Restrict who can push directly to `main`.
- Disable force pushes and branch deletion.

Minimum required checks:

- `Quality / quality`
- `Quality / gitleaks`
