---
name: restore-antigravity
description: Restore Antigravity Manager, CLI, IDE, or Extension to their original unpatched state. Use this after a failed patch, before uninstalling, or to revert changes.
---

You are restoring the Antigravity application to its original state using the `agy-manager` patcher in the current working directory.

## Steps

1. Run `python manager.py status` to show the current patch state of all detected targets.

2. If all targets already show `unpatched` or `not found`, inform the user there is nothing to restore and stop.

3. Run the restore command:
   ```
   python manager.py restore
   ```

4. Run `python manager.py status` again and confirm all previously patched targets now show `unpatched`.

5. Report the result clearly:
   - On success: tell the user the original files have been restored and Antigravity should be restarted.
   - On failure: show the full error output. Remind the user that backup files (`*.agybak` and `*.app.agysignbak` on macOS) must be present for restoration to work. If they were deleted manually, restoration is not possible.

## Notes

- On macOS, `restore` also reinstates the original bundle signature from `*.app.agysignbak`.
- Backup files are created automatically when patching. If the app was updated after patching, the backups may be for an older version.
- After restoring, re-patching is possible at any time with `/patch-antigravity`.
