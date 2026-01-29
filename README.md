# Teams Always Green

[![Release](https://img.shields.io/github/v/release/alexphillips-dev/Teams-Always-Green?label=release&sort=semver)](https://github.com/alexphillips-dev/Teams-Always-Green/releases/latest)

Keep your Microsoft Teams status active without babysitting your keyboard. Teams Always Green is a lightweight Windows tray app that gently toggles Scroll Lock on a schedule you control — so your status stays green while you focus on real work.

**Why you’ll like it**
- **Set‑and‑forget:** Runs quietly in the tray.
- **Smart scheduling:** Work hours, pauses, and quick overrides.
- **Profiles:** Switch configurations in seconds.
- **Helpful logging:** Debug detail when you need it.

---

## Quick Setup (Recommended)

1) Download `QuickSetup.cmd` from the repo.  
2) Double‑click it.  
3) Choose your install folder (default: `Documents\Teams Always Green`).

The installer will download the main script and create required folders and shortcuts.

---

## Manual Install

1) Create a folder (example: `Documents\Teams Always Green`).  
2) Place `Script\Teams Always Green.ps1` inside it (create `Script` if missing).  
3) Create subfolders: `Debug`, `Logs`, `Meta`, `Settings`.  
4) Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Script\Teams Always Green.ps1"
```

---

## Usage

- Right‑click the tray icon for Start/Stop, Settings, History, Restart, and more.
- Use **Settings** for profiles, scheduling, hotkeys, appearance, and logging.

---

## Folder Layout

```
Teams Always Green\
  Script\
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

Key files:
- Logs: `Logs\Teams-Always-Green.log`
- Bootstrap: `Logs\Teams-Always-Green.bootstrap.log`
- Settings: `Settings\Teams-Always-Green.settings.json`

---

## Troubleshooting

- **App won’t appear:** Check `Debug\*.vbs.log` and `Logs\*.log`.  
- **Settings not saving:** Ensure the `Settings` folder is writable.  
- **Weird behavior after updates:** Use **Restart** from the tray.

---

## Uninstall

1) Exit the app from the tray.  
2) Remove shortcuts:
   - Startup: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Teams Always Green.lnk`
   - Start Menu: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Teams Always Green\Teams Always Green.lnk`
3) Delete the install folder.

---

## License

MIT License. See `LICENSE`.
