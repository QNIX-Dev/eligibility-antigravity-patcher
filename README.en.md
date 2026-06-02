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
  <a href="https://github.com/nikitos4683/agy-eligibility-patcher"><img src="https://img.shields.io/badge/Core_Deps-None-brightgreen?style=flat-square" alt="Core Dependencies - None"></a>
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
| **`cli`** | **Antigravity CLI** (`agy.exe`) | NOPs the function call initiating the startup eligibility warning screen. | `agy.exe` (in path or scoop directories) |
| **`manager`** | **Antigravity Manager** (Electron) | Injects a preload `fetch` interceptor hook inside the `app.asar` container. | `resources\app.asar` |
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
<summary>🛠️ <b>CLI (`agy.exe` Go Binary PE Patching)</b></summary>

The CLI application is a Go binary. The patcher parses its Portable Executable (PE) headers to locate the `.text` section:
1. It searches for the unique string `Eligibility Check`.
2. Resolves the RIP-relative `LEA` instruction pointing to the string.
3. Finds the next `call` instruction (opcode `E8`) in the execution flow.
4. Overwrites the 5-byte instruction with `NOP`s (`0x90`), bypassing the check safely.
</details>

<details>
<summary>📦 <b>Manager (`app.asar` Electron Injector)</b></summary>

The Manager packages its frontend files in an Electron ASAR archive:
1. The tool parses and decodes the ASAR header structure.
2. It extracts `dist/preload.js` and appends a custom script wrapper.
3. The injected script hooks `window.fetch` to catch `GetAuthStatus` queries.
4. When a gRPC-web JSON response is caught, it sets `authResult.hasValidAuth = true` and wipes the eligibility failure payload.
5. Finally, the tool recalculates file hashes, re-aligns structures, repacks the ASAR, and wipes the V8 cache directory.
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
