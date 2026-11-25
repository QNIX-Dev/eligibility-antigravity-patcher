---
name: patch-antigravity
description: Patch Antigravity Manager, CLI, IDE, or Extension to bypass location restrictions. Handles macOS Library Validation automatically. Use after installing or updating Antigravity.
---

You are patching the Antigravity application using the `agy-manager` patcher in the current working directory.

## Steps

1. Run `python manager.py status` to detect installed targets and their current patch state.

2. Inspect the output:
   - If the target shows `unpatched` → proceed to patch.
   - If the target shows `patched` → inform the user it is already patched and stop.
   - If the target shows `not found` → inform the user the application was not detected and suggest using `--path-<target>` to specify the path manually.

3. Patch based on platform:

   **macOS** — always use `--macos-disable-library-validation` for the `manager` or `ide` targets (Electron Library Validation conflicts with ad-hoc signing):
   ```
   python manager.py --macos-disable-library-validation patch manager
   ```
   For non-Electron targets on macOS (cli, extension):
   ```
   python manager.py patch cli
   python manager.py patch extension
   ```

   **Linux / Windows** — no extra flags needed:
   ```
   python manager.py patch manager
   ```

   To patch all detected targets at once:
   ```
   python manager.py patch
   ```
   (Add `--macos-disable-library-validation` on macOS.)

4. Run `python manager.py status` again and confirm all targeted applications show `patched`.

5. Report the result:
   - On success: tell the user to restart Antigravity for changes to take effect.
   - On failure: show the full error output and suggest checking if the app is closed, or if it needs `--macos-disable-library-validation`.

## Notes

- Backups are created automatically as `*.agybak` and (on macOS) `*.app.agysignbak`.
- To revert: use `/restore-antigravity`.
- If the app was updated, patches are overwritten — just run `/patch-antigravity` again.
- `--macos-disable-library-validation` only modifies the main executable's entitlements; it does not affect other frameworks or helpers.
