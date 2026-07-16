<h1 align="center">🚀 agy-manager</h1>
<p align="center">
  <b>A lightweight, powerful environment manager for Antigravity developer tools (location restriction bypass on Windows & Linux, multi-account profile switching on Windows)</b>
</p>

<p align="center">
  <a href="README.md">Русский</a> | <b>English</b>
</p>

<p align="center">
  <a href="https://microsoft.com/windows"><img src="https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white" alt="OS - Windows"></a>
  <a href="https://www.linux.org"><img src="https://img.shields.io/badge/OS-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="OS - Linux"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python - 3.8+"></a>
  <a href="https://github.com/QNIX-Dev/eligibility-antigravity-patcher"><img src="https://img.shields.io/badge/Core_Deps-None-brightgreen?style=flat-square" alt="Core Dependencies - None"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License - MIT"></a>
</p>

---

## 📌 Table of Contents

- [✨ Features](#features)
- [🚀 Quick Start](#quick-start)
- [🔓 Location Restriction Bypass](#bypass)
- [👥 Account Profile Manager](#accounts)
- [🔍 How it Works (Technical Details)](#details)
- [⚠️ Caveats & Warnings](#warnings)
- [📄 License](#license)

---

## <a id="features"></a>✨ Features

`agy-manager` combines two essential tools for a seamless development experience in the Antigravity ecosystem:

- 🔓 **Location Restriction Bypass:** Disable local availability blockers ("not available in your location") across all three core applications (CLI, Manager, IDE).
- 👥 **Account Profile Manager:** Safely store and quickly switch between multiple authorization profiles offline, without the need for browser-based re-authentication.
- 🎨 **Interactive TUI Dashboard:** Features a beautiful terminal interface built with `rich` and `questionary` for managing both patches and account profiles.
- ⚡ **Zero-Dependency Core:** Scriptable commands run natively using Python's standard library alone, no package installation required.
- 🛡️ **Safe & Reversible:** Automatically creates file backups (`*.agybak`) before any modification for a quick, one-click rollback.
- ⚙️ **Smart Autodetect:** Dynamically scans registry keys, system PATH, environment variables, Scoop paths, and standard Linux installation paths (such as `/opt`, `~/.local/share`, etc.) to automatically locate installations.
- 🧬 **Version-Robust Patching:** Locates instruction signatures using regex patterns rather than relying on brittle, static file offsets.

---

## <a id="quick-start"></a>🚀 Quick Start

### Option A: Interactive TUI (Recommended)

Launches the complete terminal dashboard with live status reports for managing both patches and profiles:

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Launch agy-manager:**
   ```bash
   python manager.py
   ```

*(Supports arrow-key navigation, spacebar multi-selection, and Enter key confirmations).*

---

### Option B: Scriptable CLI (No Dependencies)

Runs purely on the Python Standard Library (no installation required). Ideal for automation or direct execution from standard terminals.

| Command | Action |
| :--- | :--- |
| `python manager.py status` | Scan and display the patch status of all applications. |
| `python manager.py patch` | Patch all detected applications. |
| `python manager.py restore` | Revert all changes and restore original files. |
| `python manager.py patch <cli\|manager\|ide>` | Patch only the specified applications. |
| `python manager.py accounts <cli-manager\|ide> <action> [name1] [name2]` | Manage saved authorization profiles (see details below). |

> [!TIP]
> If your application is installed in a custom directory, you can override automatic detection by passing the path manually:
> ```bash
> python manager.py --path-cli "D:\CustomTools\agy.exe" patch cli
> ```

---

## <a id="bypass"></a>🔓 Location Restriction Bypass

The tool modifies local eligibility gates, allowing the client applications to run in restricted regions.

> [!NOTE]
> These gates are purely client-side cosmetic restrictions. Once bypassed, all backend models and tools function normally. This utility **does not** bypass server-side authentication or unlock paid features; it simply disables the local restriction screens.

### Supported Targets

| Target | Application | Patch Vector | Detection Marker |
| :---: | :--- | :--- | :--- |
| **`cli`** | **Antigravity CLI** (`agy` / `agy.exe`) | Binary-patches `agy` / `agy.exe` to neutralize the `hasValidAuth` gate check. | `agy` / `agy.exe` |
| **`manager`** | **Antigravity Manager** (Electron) | Binary-patches the Go backend `language_server` / `language_server.exe` to force the `hasValidAuth` flag to `true`. | `resources/bin/language_server` / `resources/bin/language_server.exe` |
| **`ide`** | **Antigravity IDE** (VS Code) | Patches the minified VS Code launcher script to force the `isGoogleInternal` auth branch to `true`. | `resources/app/out/main.js` |

> [!NOTE]
> **Platform Support:** All three patches (`cli`, `manager`, `ide`) are cross-platform and support both Windows and Linux. On Linux, autodetection scans standard installation prefixes (such as `/opt`, `/usr/share`, `/usr/lib`, `~/.local/share`, `~/.local/bin`, and the launcher directories of `antigravity` and `antigravity-ide` in `PATH`). For non-standard locations, specify the executable paths manually via command line options (e.g., `--path-cli`). Ensure the applications are closed before patching to prevent file locking issues. Account management (`accounts`) remains Windows-only for now.

---

## <a id="accounts"></a>👥 Account Profile Manager

Saves the current active Antigravity session under a unique profile name, allowing you to switch between profiles offline without invoking the browser.

### Management Scopes
Sessions are isolated into two independent scopes:
1. **CLI + Manager** (share a common credential stored in Windows Credential Manager).
2. **IDE** (uses its own authorization keys in the SQLite database `state.vscdb` inside VS Code).

This separation avoids database locking conflicts and lets you switch accounts for different tools independently.

### Usage in the Interactive Menu:
1. Choose **Manage accounts** in the main menu of `python manager.py`.
2. Select the target scope: **CLI + Manager** or **IDE**.
3. Use the menu options to save the current session, switch to a saved profile, delete profiles, or log out locally.

### Usage via the Command Line:
Command structure: `python manager.py accounts <cli-manager|ide> <action> [name]`

| Action | Example Command | Description |
| :--- | :--- | :--- |
| `list` (or `ls`) | `python manager.py accounts cli-manager list` | List saved profiles for the chosen scope and mark the active one. |
| `save <name>` | `python manager.py accounts cli-manager save work` | Save the current active session under the specified name. |
| `use <name>` (or `switch`) | `python manager.py accounts cli-manager use personal` | Switch to a saved profile. |
| `logout` | `python manager.py accounts cli-manager logout` | Sign out locally (allowing you to sign into another account). |
| `rename <old> <new>` (or `mv`) | `python manager.py accounts cli-manager rename work personal` | Rename a saved profile. |
| `rm <name>` | `python manager.py accounts cli-manager rm work` | Remove a saved profile. |
| `current` (or `who`) | `python manager.py accounts cli-manager current` | Print the name of the current active profile. |

---

## <a id="details"></a>🔍 How it Works (Technical Details)

<details>
<summary>🛠️ <b>CLI Patch (`agy.exe` Go Binary)</b></summary>

At startup, the CLI renders an "Eligibility Check" section. The check resides in the `handleAuthResult` routine, which reads the `hasValidAuth` field (the byte at offset `+8`) of the AuthResult returned by the server.

1. The patcher scans the binary for the unique gate instruction signature: `test rax,rax` → `je` (eligible) → `cmp byte ptr [rax+8], 0` → `jne` (eligible).
2. If `hasValidAuth` is zero, execution falls through and prints the location error.
3. The patch rewrites the `cmp byte ptr [rax+8], 0` check to `test rax,rax` (+`NOP`). Since `rax` is always non-null here, the `jne` jump is always taken, resolving the check to "eligible".
</details>

<details>
<summary>📦 <b>Manager Patch (`language_server.exe` Go Backend)</b></summary>

The Electron Manager communicates with a local Go backend `language_server.exe` via connect-rpc. The `hasValidAuth` verdict (the byte at offset `+8` of the AuthResult) is decided in a single root location — the `authclient.(*PersonalAuthValidator).Validate` function.

1. The tool searches the validator for the check signature: `cmp byte ptr [rax+8], 0` → `je` (skips token binding).
2. The check together with the jump is overwritten with `mov byte ptr [rax+8], 1` + `NOP`: the flag is forced to `true`, and neutralizing the `je` guarantees execution always falls through into the token-binding/saving branch.
3. This validator's result is what `GetAuthStatus` returns and what the login routine relies on, so a single patch covers every scenario — both the first login and subsequent restarts. The token is saved to disk and the error screen never appears.
</details>

<details>
<summary>💻 <b>IDE Patch (`main.js` VS Code Hack)</b></summary>

1. The script parses the minified entrypoint `resources/app/out/main.js` using regular expressions.
2. It looks for the minified auth branch pattern: `resetIsTierGCPTos\(\),this\.[A-Za-z_\$0-9]+\.isGoogleInternal`.
3. Replaces it with `resetIsTierGCPTos(),true` to force Google internal developer privileges.
4. Clears VS Code's system bytecode caches (`CachedData` and `Code Cache/js`) to apply modifications instantly.
</details>

<details>
<summary>👥 <b>Account Profile Manager (Offline Session Swapping)</b></summary>

Profile switching is fully offline and does not call standard logout endpoints (which would revoke tokens on the server).

1. **Storage Separation:** CLI/Manager tokens reside in Windows Credential Manager under `gemini:antigravity`. IDE tokens are read from the VS Code global SQLite DB `state.vscdb` (under `antigravityUnifiedStateSync.*` keys).
2. **Secure Persistence:** On `save`, active credentials are read, encoded, and saved back to Windows Credential Manager under unique prefixed names: `agy-manager:account:cli-manager:<name>` or `agy-manager:account:ide:<name>`.
3. **Blob Size Limit Bypass:** generic credentials in Credential Manager are limited to 2560 bytes, but the IDE's JSON state can exceed 8 KB. IDE profiles are automatically sharded into 2000-byte pieces and stored as indexed entries (`.../<index>`).
4. **Syncing and Lock Prevention:** Before writing a new profile, the active session is automatically synced to preserve any rotated session keys.
</details>

---

## <a id="warnings"></a>⚠️ Caveats & Warnings

- **Version Compatibility:** The patcher is only guaranteed to work on the **latest** versions of the applications. It relies on binary signatures tied to specific builds, so on older versions it may fail to locate the required instructions and simply do nothing — the status will show as `unknown` and no file is modified (a safe no-op). Update the app to the latest version if this happens.
- **Updates Overwrite Patches:** Updating any of the applications will overwrite the modified binaries. Re-apply the changes by running `python manager.py patch` again.
- **File Locks & Running Processes:** Make sure all target applications in the corresponding scope (CLI, Manager, or IDE) are completely closed before patching or switching profiles. Otherwise, the OS will block file writes, or the active process may overwrite the restored database credentials from its in-memory cache.
- **Token Security:** All your credentials and profiles remain completely local to your machine. They are stored inside the secure Windows Credential Manager and your local SQLite database, and are never shared with external services.
- **Terms of Service:** Modifying proprietary client-side binaries might violate the applications' Terms of Service (ToS). This project is intended solely for educational purposes—use it at your own risk.

---

## <a id="license"></a>📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
