---
name: accounts-antigravity
description: Manage Antigravity account profiles and check quota usage. On Windows, switch between saved CLI/Manager/Extension and IDE sessions, inspect live model quotas, save or remove profiles. On macOS, create, launch, list, and repair isolated desktop profiles.
---

You are managing Antigravity account profiles using the `agy-manager` patcher in the current working directory.

Start by asking the user what they want to do. Use the platform and the options below to guide them.

## macOS: Isolated Desktop Profiles

Each profile is an isolated copy of the Antigravity app with its own credentials, settings, and conversation history.

| Goal | Command |
| :--- | :--- |
| List existing profiles | `python manager.py accounts manager list` |
| Create a new profile | `python manager.py accounts manager create <name>` |
| Launch a profile window | `python manager.py accounts manager open <name>` |
| Repair an outdated profile | `python manager.py accounts manager repair <name>` |

Ask the user for the profile name when needed. After running any command, show the output and explain the result.

## Windows: Session Switching and Quota Monitoring

There are two independent scopes:
- **`cli-manager`** covers the CLI, Manager, and Extension (shared credential).
- **`ide`** covers the Antigravity IDE (separate VS Code database).

Ask the user which scope they want to work with before proceeding.

| Goal | Command |
| :--- | :--- |
| Check live quota usage | `python manager.py accounts <scope> usage` |
| List saved profiles | `python manager.py accounts <scope> list` |
| Show active profile | `python manager.py accounts <scope> current` |
| Save current session | `python manager.py accounts <scope> save <name>` |
| Switch to a saved profile | `python manager.py accounts <scope> use <name>` |
| Rename a profile | `python manager.py accounts <scope> rename <old> <new>` |
| Remove a profile | `python manager.py accounts <scope> rm <name>` |
| Sign out locally | `python manager.py accounts <scope> logout` |

### Quota display guide

When showing quota results, explain the color coding to the user:
- **Green** — quota is healthy.
- **Yellow** — less than 20% remaining.
- **Red / RATE-LIMITED** — quota is exhausted; the model is temporarily unavailable.
- **unavailable** — that quota bucket is not enabled on this account.

## Notes

- Switching profiles is fully offline; it does not call any logout endpoints or revoke tokens on the server.
- On Windows, make sure all Antigravity applications in the relevant scope are closed before switching profiles to avoid file locking or in-memory cache overwrites.
- If a quota check fails for one account, results for other accounts are still shown.
