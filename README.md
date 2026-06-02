# agy-unlock

A tiny Python tool (Windows) — **dependency-free core**, plus an optional
interactive menu (`rich` + `questionary`) — that hides the
**"Sorry, this account is ineligible … not currently available in your location"**
eligibility screen in the three Antigravity apps:

| Target | App | What it patches |
|---|---|---|
| `cli` | **Antigravity CLI** (`agy.exe`, Go binary) | NOPs the call that prints the startup eligibility banner |
| `manager` | **Antigravity** Manager (Electron, `app.asar`) | injects a tiny `fetch` hook that clears the `ineligible` verdict from the `GetAuthStatus` response |
| `ide` | **Antigravity IDE** (VS Code fork, `out/main.js`) | forces the internal-eligible auth branch (`isGoogleInternal → true`) |

## What it does (and doesn't)

These gates are **non-blocking eligibility checks** — once past them the models and
features work normally. The tool only stops the local gate screen from appearing.
It does **not** unlock anything you couldn't already use, steal, or bypass any paid
feature — it neutralizes a client-side "not available in your region" notice.

Every change is **backed up** (`<file>.agybak`) and reversible with `restore`.
Pure standard library — no pip installs, no Node required.

## Usage

### Interactive menu (recommended)

```sh
pip install -r requirements.txt   # one-time: rich + questionary
python patch.py                   # launches the interactive menu
```

A live status table of the three apps, then arrow-key menus to **patch** /
**restore** any subset (space to toggle, enter to confirm).

### Scriptable commands (no dependencies)

```sh
python patch.py status            # show patch status of all three
python patch.py patch             # patch every app it can find
python patch.py restore           # restore every app from backup
python patch.py patch ide manager # only the listed targets (cli|manager|ide)
python patch.py --path-cli "C:\custom\agy.exe" patch cli
```

The `status` / `patch` / `restore` commands use only the standard library —
`rich` + `questionary` are needed **only** for the interactive menu.

Close the relevant app first (the tool refuses to touch a locked file).
After patching the IDE/Manager it clears their V8 byte-code caches automatically.

## How it finds your install

No hard-coded paths or versions. For each app it searches the usual roots —
per-user & machine `…\Programs`, `Program Files`, `Program Files (x86)`,
`%LOCALAPPDATA%`, the Windows **registry** (`Uninstall` → `InstallLocation` of
anything named *Antigravity*), the **PATH** (for `agy`), and Scoop if present —
then matches each app by a **structural marker file**, not by name/version:

| App | Marker |
|---|---|
| cli | `agy.exe` (on PATH or `…\agy\bin\`) |
| manager | `…\resources\app.asar` |
| ide | `…\resources\app\out\main.js` |

If your install lives somewhere unusual, point at it with `--path-cli` /
`--path-manager` / `--path-ide`.

## Why it's version-robust

Nothing is hard-coded to a build:

- **cli** — finds the unique `Eligibility Check` string, follows the RIP-relative
  `LEA` that references it, and NOPs the first `call rel32` after it. Survived an
  `agy.exe` auto-update during testing (located the new offset on its own).
- **manager** — parses & rebuilds the `app.asar` in pure Python (preserves the
  `app.asar.unpacked` entries and recomputes per-file integrity), appending the
  hook to `dist/preload.js`.
- **ide** — a regex (`resetIsTierGCPTos(),this.<X>.isGoogleInternal → …,true`)
  that matches the auth gate regardless of the minified variable name / version.

## Caveats

- **Windows x64.** Built against CLI 1.0.x, Manager 2.0.6, IDE 2.0.3.
- **App updates revert it** — just run `python patch.py patch` again afterwards.
- Modifying these proprietary apps may be against their Terms of Service. It's a
  cosmetic, local, reversible tweak — use at your own risk.

## License

MIT — see [LICENSE](LICENSE).
