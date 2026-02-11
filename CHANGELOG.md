# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]
### Added
- Global UI safe-action wrapper for settings actions to reduce unhandled UI exceptions.
- Deterministic log event IDs (`E=<ContextCode-NNN>`) in runtime logs.
- Additional quality tests for stock profiles, update-check coverage, themed hover handlers, and release discipline.
- Startup performance budget helpers and CI tests for stage timing parsing/budget evaluation.
- UI module contract validation to ensure required exported functions are present when tray/settings/history modules load.

### Changed
- Profile button hover handlers now preserve theme-aware foreground colors.
- Settings/state persistence now uses atomic file writes with flush+replace semantics to reduce partial-write corruption risk.

## [1.0.0] - 2026-02-11
### Added
- Initial public release of Teams Always Green.
