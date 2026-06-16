<h1 align="center">🚀 agy-unlock</h1>
<p align="center">
  <b>A lightweight, robust patcher designed to bypass cosmetic location restrictions in Antigravity apps on Windows</b>
</p>

<p align="center">
  <a href="README.md">Русский</a> | <b>English</b>
</p>

<p align="center">
  <a href="https://microsoft.com/windows"><img src="https://img.shields.io/badge/OS-Windows-0078D6?style=flat-square&logo=windows&logoColor=white" alt="OS - Windows"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python - 3.8+"></a>
  <a href="https://github.com/QNIX-Dev/antigravity-eligibility-patcher"><img src="https://img.shields.io/badge/Core_Deps-None-brightgreen?style=flat-square" alt="Core Dependencies - None"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License - MIT"></a>
</p>

---

> [!NOTE]
> These gates are local client-side restrictions. Once bypassed, the backend models and features function normally. This tool **does not** unlock paid features or bypass server-side authentication; it simply disables the local location blocker.

---

## ✨ Features

- ⚡ **Zero-Dependency Core:** Patcher commands (`status`, `patch`, `restore`) run natively using Python's standard library.
- 🎨 **Interactive Terminal UI:** Features a stylized console dashboard built with `rich` and `questionary`.
- 🛡️ **Safe & Reversible:** Creates automatic backups (`*.agybak`) before modifying any file, allowing one-click rollback.
- ⚙️ **Autodetect & Discover:** Searches registry keys, system PATH, environment paths, and Scoop directories to find installations dynamically. No hardcoded directories!
- 🧬 **Version-Robust Patching:** Locates code signatures structures (using regex and relative instruction offsets) rather than static file offsets.

---

## 📱 Supported Targets

| Target | Application | Patch Vector | Detection Marker |
| :---: | :--- | :--- | :--- |
| **`cli`** | **Antigravity CLI** (`agy.exe`) | Binary-patches `agy.exe` to neutralize the `hasValidAuth` gate check. | `agy.exe` (in path or scoop directories) |
| **`manager`** | **Antigravity Manager** (Electron) | Binary-patches the Go backend `language_server.exe` to force the `hasValidAuth` flag to `true`. | `resources\bin\language_server.exe` |
| **`ide`** | **Antigravity IDE** (VS Code) | Patches the minified VS Code launcher script to force `isGoogleInternal` auth branch to `true`. | `resources\app\out\main.js` |

---

## 🚀 Quick Start

### Option A: Interactive Dashboard (Recommended)

To launch the interactive CLI menu with status summaries:

1. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Launch the patcher:**
   ```bash
   python patch.py
   ```

*(Provides arrow-key navigation, spacebar multi-selection, and live status reports).*

---

### Option B: Scriptable Command Line (No Dependencies)

Runs purely on the Python Standard Library (no `pip install` required).

| Command | Action |
| :--- | :--- |
| `python patch.py status` | Scan and display the status of all applications. |
| `python patch.py patch` | Patch all detected applications (creates backups automatically). |
| `python patch.py restore` | Revert all changes and restore original files. |
| `python patch.py patch ide` | Only patch specified apps (e.g. `ide`, `manager`, or `cli`). |

> [!TIP]
> If your application is installed in a custom directory, you can override automatic detection by passing the path manually:
> ```bash
> python patch.py --path-cli "D:\CustomTools\agy.exe" patch cli
> ```

---

## 🔍 How it Works (Technical Details)

<details>
<summary>🛠️ <b>CLI (`agy.exe` Go binary patch)</b></summary>

The CLI prints a cosmetic "Eligibility Check" section at startup. The decision to show it is made in `handleAuthResult`, which reads the `hasValidAuth` field (the byte at offset `+8`) of the AuthResult returned **by the server**.

1. The patcher scans the binary for a gate signature that is unique across the whole file, and refuses to run if it is missing or occurs more than once (a guard against unknown versions).
2. The signature pinpoints the check: `test rax,rax` → `je` (eligible) → `cmp byte ptr [rax+8], 0` → `jne` (eligible). When `hasValidAuth` is zero, execution falls through and prints "Eligibility check failed".
3. The `cmp byte ptr [rax+8], 0` is rewritten to `test rax,rax` (+`NOP`). Since `rax` is known non-null here, the `jne` always takes the eligible branch.
4. As a result the restriction section never renders, regardless of the server response.
</details>

<details>
<summary>📦 <b>Manager (`language_server.exe` Go Backend Patch)</b></summary>

The Manager talks to a local Go backend, `language_server.exe` (over connect-rpc), and that backend is what issues the eligibility verdict. More importantly, when it marks the account as ineligible it never persists the OAuth token, forcing a fresh browser login on every launch.

1. The tool scans the binary for a signature that is unique across the whole file, and refuses to run if it is missing or occurs more than once (a guard against unknown versions).
2. The signature pinpoints the `hasValidAuth` check inside the login-validation routine — a `cmp byte ptr [rax+8], 0` immediately followed by the token being attached to the auth status.
3. That check is overwritten with `mov byte ptr [rax+8], 1` + 2×`NOP` (6 bytes total; the `NOP`s neutralize the now-dead jump).
4. As a result the account is always treated as valid: the token is attached, persisted to disk, and the cosmetic restriction screen no longer appears.
</details>

<details>
<summary>💻 <b>IDE (`main.js` VS Code Hack)</b></summary>

The IDE is built on top of VS Code:
1. It scans `resources/app/out/main.js` using regular expressions.
2. Identifies the minified auth evaluator pattern:
   `resetIsTierGCPTos\(\),this\.[A-Za-z_\$0-9]+\.isGoogleInternal`
3. Replaces it with `resetIsTierGCPTos(),true` to force Google internal developer privileges.
4. Wipes the system's VS Code compiled bytecode caches (`CachedData` and `Code Cache/js`) to ensure modifications apply instantly.
</details>

---

## ⚠️ Caveats & Warnings

- **Updates Overwrite Patches:** Since target files are modified locally, updating any of the apps will overwrite the patches. Just run `python patch.py patch` again to re-apply.
- **File Locks:** Make sure the corresponding application is completely closed before running the patcher; otherwise, file handles will be locked and patching will fail.
- **Terms of Service:** Modifying proprietary client code may violate the applications' Terms of Service. This is an educational showcase of client-side patch execution—use it responsibly.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
