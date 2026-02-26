# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]
### Added
- None yet.

### Changed
- Reorganized repository structure for maintainability:
  - `Tools` split into `Tools/ci`, `Tools/release`, `Tools/local`, and `Tools/config`.
  - Test suites grouped under `Tests/Unit`, `Tests/Integration`, `Tests/Smoke`, and `Tests/Quality`.
  - Updated workflows/docs to use the new paths.

## [1.0.2] - 2026-02-26
### Added
- Branch-aware QuickSetup UX with persistent `Channel: main/dev` labeling, explicit channel chooser fallback, and dev-channel warning flow.
- OneDrive-aware install/uninstall safeguards and diagnostics to reduce business-user sync/lock issues.
- Full uninstall wizard flow with in-window progress, details pane, and dry-run validation mode.
- Uninstall lock handling safeguards: likely-locker process detection, optional force-close path, retry/backoff, and lock diagnostics.
- Expanded uninstall integration and quality tests for dry-run behavior, launcher flow, working-directory edge cases, and locked-path cleanup.

### Changed
- QuickSetup channel detection now prioritizes explicit runtime signals (`TAG_QUICKSETUP_CHANNEL`, command context, invocation text, history) before hash/git fallback for deterministic main/dev installs.
- QuickSetup integrity flow was hardened for XML line-ending hash normalization and signed manifest freshness verification.
- QuickSetup launcher/readme install commands were standardized for deterministic channel selection.
- Uninstall VBS/PowerShell relaunch behavior was hardened for reliable interactive startup with improved telemetry.
- Uninstall UI was refined to keep users in one continuous flow with clearer guidance and completion states.
- Uninstall retry behavior for OneDrive-like locks was tuned to reduce total wait time while preserving diagnostics.

## [1.0.1] - 2026-02-24
### Added
- Required QuickSetup manifest signature verification with a pinned RSA public key.
- Added public verification keys for QuickSetup and update-asset signature validation.
- Added automated tag-based release workflow to sign and publish release assets.
- Added `Tools/Generate-UpdateSignature.ps1` for deterministic update signature generation and verification.

### Changed
- Quality and release checks now enforce QuickSetup manifest signature validation.
- Release prep now verifies manifest freshness with required signature validation.
- Security standards and developer release docs updated for the signed release process.

## [1.0.0] - 2026-02-11
### Added
- Initial public release of Teams Always Green.
