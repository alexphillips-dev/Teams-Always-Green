# <img src="https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/refs/heads/main/Meta/Icons/Tray_Icon.ico" alt="Teams Always Green" width="28" height="28"> Teams Always Green

[![Release](https://img.shields.io/github/v/release/alexphillips-dev/Teams-Always-Green?label=release&sort=semver)](https://github.com/alexphillips-dev/Teams-Always-Green/releases/latest)
[![License](https://img.shields.io/github/license/alexphillips-dev/Teams-Always-Green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](README.md#quick-start-3-steps)

Keep your Microsoft Teams status active without babysitting your keyboard. Teams Always Green is a lightweight Windows tray app that gently toggles Scroll Lock on a schedule you control -- so your status stays green while you focus on real work.

**Why you'll like it**
- **Set-and-forget:** Runs quietly in the tray.
- **Smart scheduling:** Work hours, pauses, and quick overrides.
- **Profiles:** Switch configurations in seconds.
- **Helpful logging:** Debug detail when you need it.
- **Language support:** English, Español, Français, Deutsch (auto-detect + manual).

---

## Quick Setup (Recommended)

**One-line install (PowerShell):**

```powershell
irm "https://raw.githubusercontent.com/alexphillips-dev/Teams-Always-Green/main/QuickSetup.ps1?ts=$([guid]::NewGuid())" | iex
```

1) Download `QuickSetup.cmd` from the repo (it always pulls the latest installer).  
2) Double-click it.  
3) Choose your install folder (default: `Documents\Teams Always Green`).

The installer downloads the app scripts/modules, validates integrity (when the manifest is available),
creates required folders, and can set up shortcuts. A setup summary appears at the end.
Optional: choose **portable mode** to skip shortcuts. Setup logs are saved to `%TEMP%\TeamsAlwaysGreen-QuickSetup.log`.

---

## Quick Start (3 steps)

1) **Install** with Quick Setup.  
2) **Start** from the tray icon.  
3) **Customize** in Settings (schedule, profiles, hotkeys, logging).

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
3) Create subfolders: `Debug`, `Logs`, `Meta`, `Settings`.  
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
  Uninstall-Teams-Always-Green.ps1
  QuickSetup.ps1
  QuickSetup.cmd
  Teams Always Green.VBS
  Debug\
  Logs\
  Meta\
    Icons\
  Settings\
```

Key files:
- Logs: `Logs\Teams-Always-Green.log`
- Bootstrap: `Logs\Teams-Always-Green.bootstrap.log`
- Settings: `Settings\Teams-Always-Green.settings.json`
- State: `Settings\Teams-Always-Green.state.json`

---

## Troubleshooting

- **App won't appear:** Check `Debug\*.vbs.log` and `Logs\*.log`.  
- **Settings not saving:** Ensure the `Settings` folder is writable.  
- **Weird behavior after updates:** Use **Restart** from the tray.

---

## Security & Privacy

- **Local-only behavior:** No data collection.
- **Network access:** Used only for update checks (if enabled).
- **Files created:** Logs and settings remain inside your install folder.

---

## Uninstall

**Standard install (recommended):** Use the Start Menu shortcut  
`Teams Always Green` → **Uninstall Teams Always Green**

**Manual/portable uninstall:**
1) Exit the app from the tray.  
2) Remove shortcuts (if any):
   - Startup: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Teams Always Green.lnk`
   - Start Menu: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Teams Always Green\Teams Always Green.lnk`
3) Delete the install folder.

---

## License

MIT License. See `LICENSE`.
