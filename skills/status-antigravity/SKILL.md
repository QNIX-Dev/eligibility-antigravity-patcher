---
name: status-antigravity
description: Check the current patch status of all detected Antigravity applications (CLI, Manager, IDE, Extension). Use this to see what is patched, unpatched, or not found before deciding to patch or restore.
---

You are checking the patch status of Antigravity applications using the `agy-manager` patcher in the current working directory.

## Steps

1. Run:
   ```
   python manager.py status
   ```

2. Present the results clearly for each target:
   - `patched` — the application has been patched successfully.
   - `unpatched` — the application is installed but not yet patched. Suggest running `/patch-antigravity`.
   - `not found` — the application was not detected automatically. Mention that a custom path can be provided via `--path-<target>` if it is installed in a non-standard location.

3. If all detected targets are unpatched, suggest `/patch-antigravity`.
4. If all detected targets are patched, confirm everything is in order.
5. If some are patched and some are not, highlight the difference and suggest patching the remaining ones.
