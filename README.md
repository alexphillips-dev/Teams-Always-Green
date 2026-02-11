<p align="center">
  <img src="Meta/Readme/Banner.png" alt="Teams Always Green Banner" width="100%" />
</p>

# <img src="https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/refs/heads/main/Meta/Icons/Tray_Icon.ico" alt="Teams Always Green" width="28" height="28"> Teams Always Green

[![Release](https://img.shields.io/github/v/release/alexphillips-dev/Teams-Always-Green?label=release&sort=semver)](https://github.com/alexphillips-dev/Teams-Always-Green/releases/latest)
[![License](https://img.shields.io/github/license/alexphillips-dev/Teams-Always-Green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](README.md#requirements)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-blue)](README.md#requirements)

Keep your Microsoft Teams status active without babysitting your keyboard. Teams Always Green is a lightweight Windows tray app that gently toggles Scroll Lock on a schedule you control -- so your status stays green while you focus on real work.

**Why you'll like it**
- **Set-and-forget:** Runs quietly in the tray.
- **Smart scheduling:** Work hours, pauses, and quick overrides.
- **Profiles:** Switch configurations in seconds.
- **Helpful logging:** Debug detail when you need it.
- **Language support:** English, Spanish, French, German (auto-detect + manual).

---

## Quick Setup (Recommended)

**One-line install (PowerShell):**

```powershell
irm "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main/Script/QuickSetup/QuickSetup.ps1?ts=$([guid]::NewGuid())" | iex
```

1) Download `Script/QuickSetup/QuickSetup.cmd` from the repo (it always pulls the latest installer).  
2) Double-click it.  
3) Choose your install folder (default: `Documents\Teams Always Green`).

The installer downloads the app scripts/modules, validates integrity with `QuickSetup.manifest.json`,
creates required folders, and can set up shortcuts. A setup summary appears at the end.
Optional: choose **portable mode** to skip shortcuts. Setup logs are saved to `%TEMP%\TeamsAlwaysGreen-QuickSetup.log`.

---

## Quick Start (3 steps)

1) **Install** with Quick Setup.  
2) **Start** from the tray icon.  
3) **Customize** in Settings (schedule, profiles, hotkeys, logging).

---

## Requirements

- Windows 10/11
- PowerShell 5.1 or 7.x

---

## Common Setups

- **Work hours only:** Enable Schedule and set Start/End time.
- **No distractions:** Disable balloon tips + use Quiet Mode.
- **Multiple profiles:** Create "Office" and "Off-hours" profiles and switch from tray.
- **Hands-free:** Use hotkeys to Start/Stop or Pause without opening Settings.

---

## Manual Install

1) Create a folder (example: `Documents\Teams Always Green`).  
2) Copy the entire `Script\` folder from the repo into it.  
3) Copy `Meta\Icons\` and `VERSION` from the repo into the install folder.  
4) Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Script\Teams Always Green.ps1"
```

---

## Usage

- Right-click the tray icon for Start/Stop, Settings, History, Restart, and more.
- Use **Settings** for profiles, scheduling, hotkeys, appearance, and logging.

---

## Folder Layout

```
Teams Always Green\
  Script\
    Teams Always Green.ps1
    Core\
    Features\
    I18n\
    Tray\
    UI\
  Script\Uninstall\
    Uninstall-Teams-Always-Green.ps1
    Uninstall-Teams-Always-Green.vbs
  Script\QuickSetup\
    QuickSetup.ps1
    QuickSetup.cmd
    QuickSetup.manifest.json
  Teams Always Green.VBS
  CHANGELOG.md
  Debug\
  Meta\
    Icons\
    Readme\
      Banner.png
```

Runtime data (standard install):
- Logs: `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs\Teams-Always-Green.log`
- Bootstrap: `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs\Teams-Always-Green.bootstrap.log`
- Settings: `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings\Teams-Always-Green.settings.json`
- State: `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings\Teams-Always-Green.state.json`

Portable mode stores runtime data in the install folder (`Logs\`, `Settings\`, `Meta\`).

---

## Troubleshooting

- **App won't appear:** Check `Debug\*.vbs.log` and `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs\*.log`.  
- **Settings not saving:** Ensure `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings` is writable.  
- **Weird behavior after updates:** Use **Restart** from the tray.

---

## Security & Privacy

- **Local-only behavior:** No data collection.
- **Network access:** Used only for update checks (if enabled).
- **Files created:** Logs/settings/state are stored in your user profile (`%LOCALAPPDATA%\TeamsAlwaysGreen`) for standard installs, or in the install folder for portable mode.
- **Profile integrity:** Exported profile files include a SHA-256 signature; imports validate signatures and can block unsigned/invalid profiles in strict mode.

### Security Hardening

- **Security Mode bundle:** A single toggle in **Settings -> Advanced** to enforce strict import/update policy, update hash/signature requirements, permission hardening, and safer path behavior.
- **Strict imports:** `StrictSettingsImport` and `StrictProfileImport` can block unknown or malformed keys during imports.
- **Trusted update source:** Updates are validated against configured `UpdateOwner`/`UpdateRepo` and trusted GitHub URLs.
- **Update integrity gates:** `UpdateRequireHash` and `UpdateRequireSignature` can require SHA-256 and detached signature validation before applying updates.
- **Script signature policy:** `RequireScriptSignature` with optional `TrustedSignerThumbprints` enforces Authenticode trust at startup.
- **Path protections:** External path usage can be disabled; unsafe link-style reparse paths are blocked for sensitive loads.
- **Rate limiting:** Update checks and import actions are throttled to reduce abuse loops.
- **Audit chain:** Security/audit log entries include a hash chain to help detect tampering.

---

## Developer Quality & Release

Versioning discipline:
- `VERSION` must be `major.minor.patch` (SemVer).
- `CHANGELOG.md` must include both `## [Unreleased]` and a section for the current `VERSION`.

1. Run local quality checks: `powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Invoke-QualityChecks.ps1`
2. Refresh installer manifest: `powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Generate-QuickSetupManifest.ps1`
3. Sign release scripts (certificate in cert store required): `powershell -NoProfile -ExecutionPolicy Bypass -File .\Tools\Sign-Release.ps1 -CertificateThumbprint <THUMBPRINT>`
4. `.github/workflows/quality.yml` runs analyzer + Pester + manifest freshness checks.
5. `.github/workflows/release-prep.yml` regenerates and commits `Script/QuickSetup/QuickSetup.manifest.json` on demand before release.

---

## Uninstall

**Standard install (recommended):** Use the Start Menu shortcut  
`Teams Always Green` -> **Uninstall Teams Always Green**

**Manual/portable uninstall:**
1) Exit the app from the tray.  
2) Remove shortcuts (if any):
   - Startup: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Teams Always Green.lnk`
   - Start Menu: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Teams Always Green\Teams Always Green.lnk`
3) Delete the install folder.

---

## License

MIT License. See `LICENSE`.
