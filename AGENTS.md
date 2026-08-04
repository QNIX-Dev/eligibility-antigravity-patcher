# AGENTS.md

## Project overview

This repository contains a cross-platform Antigravity patcher and account manager.

- `manager.py` is the application and must remain usable as a standalone Python script.
- Core patching and scriptable commands use only the Python standard library.
- `rich` and `questionary` are optional and are used only by the interactive menu.
- `tests/test_manager.py` contains the regression and transaction tests.
- `README.md` and `README.en.md` are equivalent Russian and English documentation.

## Required validation

After changing Python code, run:

```powershell
python -m py_compile manager.py tests\test_manager.py
python -m unittest discover -s tests -v
git diff --check
```

Do not consider a patching change complete until the entire test suite passes.

## Binary patch safety

- Preserve the safe-failure behavior: unsupported, missing, duplicate, mixed, or ambiguous signatures must not modify a target.
- Search binary signatures only inside executable PE, ELF, or Mach-O ranges.
- Preserve architecture-aware routing. Every architecture-specific `Gate` must declare `arch="x64"` or `arch="arm64"`.
- Preserve backup verification, the pre-write rescan, post-write verification, rollback, and `fsync` behavior.
- Never replace uniqueness checks with a first-match-wins implementation.
- Never use a fixed file offset as the primary way to locate a gate.
- Test both `unpatched` and `patched` recognition for every supported signature.

## Signature style

- Write every original and patched signature directly inside its `Gate` as an inline raw-bytes regular expression (`rb"..."`).
- Do not build signatures from named regex fragments, module-level signature variables, f-strings, joins, or concatenated helper constants.
- Adjacent raw-bytes literals inside the same `Gate` argument are allowed only to wrap a long regex across lines; Python must concatenate them implicitly.
- Keep the complete signature visible at the `Gate` declaration so it can be reviewed as one unit.
- Use regex wildcards or byte classes only for bytes that genuinely vary, such as relative branch displacements. Keep opcode, register, bit-number, and stable surrounding-instruction bytes constrained.
- Add a short instruction-level comment above each binary gate explaining what the regex matches and what the replacement does.
- A context callback such as `accept=` may be used when required to validate bytes immediately outside the regex match, but the signature itself must still remain an inline regex in the `Gate` declaration.
- When a signature changes, add a regression fixture using bytes from the real build and retain coverage for older supported layouts.

Example of the required formatting:

```python
EXAMPLE_GATE = Gate(
    rb"\x01\x02....\x03"
    rb"\x04\x05",
    rb"\x06\x07....\x03"
    rb"\x04\x05",
    b"\x06\x07", desc="example", arch="arm64")
```

Do not rewrite the example above as separately named prefix, branch, or tail variables.

## Testing new application builds

- Never patch a user-supplied archive or disk image directly.
- Extract only the required files into a uniquely named temporary directory.
- Confirm the executable format, architecture, executable ranges, signature count, state, and file offset.
- Perform patch/status/restore testing only on temporary extracted copies.
- Verify that restore returns the temporary file to the recognized `unpatched` state.
- Remove temporary extraction files after validation.

## Documentation

- Keep `README.md` and `README.en.md` synchronized.
- When instruction signatures change, update the corresponding ARM64 or x64 paragraphs in the technical-details sections of both files.
- Preserve the existing Markdown/HTML structure and formatting unless the task explicitly requests a documentation redesign.

## Account-management changes

- Treat credential blobs, OAuth tokens, refresh tokens, and profile contents as secrets. Do not print them in tests, diagnostics, or responses.
- Use mocks or temporary SQLite databases for account tests.
- Avoid repeated Credential Manager and SQLite reads within a single operation, but do not introduce persistent caches that can hide external login changes.

## Scope and style

- Keep unrelated user changes intact.
- Prefer focused edits over broad rewrites.
- Preserve cross-platform behavior on Windows, Linux, Intel macOS, and Apple Silicon.
- Do not add a required runtime dependency without explicit approval.
- Keep command-line behavior and exit codes backward compatible unless the task explicitly changes them.
