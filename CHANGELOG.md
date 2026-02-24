# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]
### Added
- None yet.

### Changed
- None yet.

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
