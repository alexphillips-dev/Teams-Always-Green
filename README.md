# Teams Always Green

[![Release](https://img.shields.io/github/v/release/alexphillips-dev/Teams-Always-Green?label=release&sort=semver)](https://github.com/alexphillips-dev/Teams-Always-Green/releases/latest)

Keep your Microsoft Teams status active without babysitting your keyboard. Teams Always Green is a lightweight Windows tray app that gently toggles Scroll Lock on a schedule you control—so your status stays green while you focus on real work.

**Why you’ll like it**
- **Set it and forget it:** Start once, it runs quietly in the tray.
- **Smart scheduling:** Work hours, pause windows, and one-click overrides.
- **Profiles:** Switch configs for home, office, or on-call in seconds.
- **Deep logging when you need it:** Debug mode, diagnostics, and history.

---

## Features at a Glance

- Tray app with Start/Stop/Toggle, Restart, and Exit
- Profiles with per-profile settings (intervals, colors, hotkeys, scheduling)
- Scheduling + pause controls (including one-time pauses)
- Global hotkeys for quick control
- Live Settings UI with Status, History, and Diagnostics
- Robust logging with rotation and export

---

## Quick Setup (Recommended)

Download and run the single-file bootstrapper:

1) Download `QuickSetup.cmd` from the repo.
2) Double-click it.
3) Choose your install folder (default: `Documents\Teams Always Green`).

The installer will:
- Download `Teams Always Green.ps1`
- Create required folders (`Debug`, `Logs`, `Meta`, `Settings`)
- Create Start Menu, Desktop, and Startup shortcuts

---

## Manual Install

1) Create an install folder (example: `Documents\Teams Always Green`).
2) Copy `Teams Always Green.ps1` into that folder.
3) Create subfolders: `Debug`, `Logs`, `Meta`, `Settings`.
4) Run the script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Teams Always Green.ps1"
```

---

## Folder Layout

```
Teams Always Green\
  Teams Always Green.ps1
  QuickSetup.ps1
  QuickSetup.cmd
  Teams Always Green.VBS
  Debug\
  Logs\
  Meta\
    Icons\
  Settings\
```

### Important Files

- Logs: `Logs\Teams-Always-Green.log`
- Bootstrap log: `Logs\Teams-Always-Green.bootstrap.log`
- Settings: `Settings\Teams-Always-Green.settings.json`
- Settings backups: `Settings\Teams-Always-Green.settings.json.bak#`

---

## Usage

- The tray icon controls everything.
- Right-click the tray icon for Start/Stop, Settings, History, Restart, and more.
- Use **Settings** for profiles, scheduling, hotkeys, appearance, and logging.

---

## Settings Overview (User-Friendly)

### General
- Interval (how often to toggle)
- Start with Windows
- Quiet Mode
- Date/Time format controls
- Remember last Settings tab

### Scheduling
- Work hours (start/end)
- Weekday selection
- Suspend schedule until

### Hotkeys
- Toggle Now
- Start/Stop
- Pause/Resume

### Logging
- Log level (DEBUG/INFO/WARN/ERROR/FATAL)
- Log max size + retention
- Log folder
- Clear log

### Profiles
- Create, rename, duplicate, and load profiles
- Switch instantly without restart

### Diagnostics
- Export diagnostics bundle
- Report issue shortcut

---

## History Window

The tray **History** menu shows recent toggle events with:
- Time
- Result (Succeeded/Failed)
- Source (tray/hotkey/schedule)
- Message

Includes filters, search, copy, and export.

---

## Logging & Debug Mode

- Logs are written to your chosen log folder.
- Debug Mode temporarily increases logging detail and turns on all log categories for troubleshooting.
- Log rotation prevents runaway file size.

---

## Troubleshooting

- **“Already running”** ? Check for a lingering PowerShell process for the script.
- **Startup issues** ? Check `Logs\Teams-Always-Green.bootstrap.log`.
- **Settings not saving** ? Verify the `Settings` folder is writable.

---

## Uninstall

1) Exit the app from the tray.
2) Remove Startup shortcut:
   - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Teams Always Green.lnk`
3) Remove Start Menu shortcut:
   - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Teams Always Green\Teams Always Green.lnk`
4) Delete the install folder.

---

## Updating

- Re-run `QuickSetup.cmd` to pull the latest script.
- Or replace `Teams Always Green.ps1` manually.

---

## Security Notes

- No admin rights required.
- All settings are stored locally in the `Settings` folder.
- Uses only standard Windows APIs and PowerShell.

---

## License

MIT License. See `LICENSE`.

