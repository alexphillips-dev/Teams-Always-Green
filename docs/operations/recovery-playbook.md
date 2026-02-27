# Recovery Playbook

Use this playbook when install, update, runtime, or uninstall behavior is not healthy.

## 1) Collect logs first

- Runtime logs:
  - `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs\Teams-Always-Green.log`
  - `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs\Teams-Always-Green.bootstrap.log`
- QuickSetup log:
  - `%TEMP%\TeamsAlwaysGreen-QuickSetup.log`
- Uninstall logs:
  - `%TEMP%\TeamsAlwaysGreen-UninstallLauncher.log`
  - `%TEMP%\TeamsAlwaysGreen-Uninstall-*.log`
  - `%TEMP%\TeamsAlwaysGreen-Uninstall-*.json`

## 2) Install/QuickSetup failures

1. Confirm you are using the intended channel (`main` or `dev`) shown in the installer header.
2. Re-run QuickSetup from a clean PowerShell session.
3. Check `%TEMP%\TeamsAlwaysGreen-QuickSetup.log` for:
   - trusted URL blocks
   - manifest signature validation failures
   - file hash mismatches
4. If hash/signature mismatch appears, refresh repository state and regenerate manifest/signature:
   - `.\Tools\release\Generate-QuickSetupManifest.ps1 -Sign -ManifestPrivateKeyPath <PRIVATE_KEY_XML_PATH>`

## 3) Runtime failures (app does not stay running / odd behavior)

1. Open bootstrap/runtime logs and capture the first fatal/error event.
2. Validate local app data folders are writable:
   - `%LOCALAPPDATA%\TeamsAlwaysGreen\Logs`
   - `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings`
3. Reset to known-good settings by backing up and removing:
   - `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings\Teams-Always-Green.settings.json`
   - `%LOCALAPPDATA%\TeamsAlwaysGreen\Settings\Teams-Always-Green.state.json`
4. Relaunch via `Teams Always Green.VBS`.

## 4) Update failures

1. Check runtime logs for update gate messages (`hash`, `signature`, `trusted URL`).
2. Verify `VERSION` and release notes alignment.
3. Confirm release assets include:
   - signed `Teams Always Green.ps1`
   - detached update signature (`.sig`)
   - SBOM/provenance/checksum files
4. If needed, disable update checks temporarily in Settings while triaging.

## 5) Uninstall failures

1. Run uninstall again and review `%TEMP%\TeamsAlwaysGreen-Uninstall-*.log`.
2. Use **Dry run** first to validate path resolution and expected actions.
3. If lock-related retries persist:
   - close shells/editors pointing at the install directory
   - avoid uninstalling from OneDrive-managed sync roots when possible
   - rerun with **Force close likely locking apps** (advanced)
4. If partial cleanup remains, manually delete residual paths from the uninstall JSON report.

## 6) CI/release gate failures

1. Run local quality checks:
   - `.\Tools\ci\Invoke-QualityChecks.ps1`
2. Run install/uninstall smoke:
   - `.\Tools\ci\Invoke-InstallUninstallSmoke.ps1`
3. Re-check privacy scan:
   - `.\Tools\ci\Find-PrivacyLeaks.ps1 -AllTracked`
4. For release failures:
   - ensure `UPDATE_SIGNING_PRIVATE_KEY_XML` exists
   - ensure `AUTHENTICODE_CERT_PFX_BASE64` and `AUTHENTICODE_CERT_PASSWORD` are set

