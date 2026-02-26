# Architecture Overview

## Runtime Model

`app/runtime/Teams Always Green.ps1` is the app entry point. It initializes runtime state, loads feature modules, creates the tray UI, and runs the toggle loop.

## Module Boundaries

- `app/runtime/Core/*`
  - Shared app metadata, paths, settings migration/validation, runtime helpers, and logging primitives.
- `app/runtime/Features/UpdateEngine.ps1`
  - Update discovery, trust validation, hash/signature verification, and update apply flow.
- `app/runtime/Features/Hotkeys.ps1`
  - Hotkey parsing and registration lifecycle.
- `app/runtime/Features/Scheduling.ps1`
  - Schedule parsing and runtime schedule-block decisions.
- `app/runtime/Features/Profiles.ps1`
  - Profile runtime helpers (usage split summaries).
- `app/runtime/Tray/Menu.ps1`
  - Tray menu construction/actions and labels.
- `app/runtime/UI/*.ps1`
  - Settings and History dialogs.

All runtime feature/UI modules are loaded via trusted-path runtime import helpers and contract checks.

## Startup Flow (Simplified)

1. Entry script initializes paths, strict mode, and runtime settings.
2. Core/runtime trust checks validate module paths.
3. Feature modules load (`UpdateEngine`, `Hotkeys`, `Scheduling`, `Profiles`).
4. Tray/UI modules load and contracts are validated.
5. Settings are loaded/migrated and runtime state is applied.
6. Hotkeys/timers start and tray status loop begins.

## Installer Flow (QuickSetup)

1. User selects install location/mode in wizard.
2. Installer resolves source (local repo or trusted GitHub raw URL).
3. `QuickSetup.manifest.json` is required and validated.
4. Every downloaded file hash is verified before install completes.
5. Finalization creates shortcuts/startup links (unless portable mode), then summary actions launch/open.

## Data Paths

- Standard mode data root: `%LOCALAPPDATA%\TeamsAlwaysGreen`
  - `Logs\`, `Settings\`, `Meta\`
- Portable mode data root: install directory
  - `Logs\`, `Settings\`, `Meta\`

