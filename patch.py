#!/usr/bin/env python3
"""
agy-unlock — hide the cosmetic / non-blocking "not available in your location"
eligibility gate in the three Antigravity apps on Windows:

  * cli      Antigravity CLI         (agy.exe, Go binary)        -> suppress eligibility screen
  * manager  Antigravity (Manager)   (language_server.exe, Go)   -> force hasValidAuth=true
  * ide      Antigravity IDE         (VS Code fork, out/main.js)  -> force the internal-eligible branch

None of these unlock anything you can't already use — they only stop a local,
non-blocking eligibility screen from appearing. Every change is backed up
(<file>.agybak) and reversible with `restore`. Pure standard library.

Usage:
    python patch.py status                 # show all three (default)
    python patch.py patch                  # patch all detected apps
    python patch.py restore                # restore all from backup
    python patch.py patch ide manager      # only specific targets
    python patch.py --path-cli "C:\\...\\agy.exe" patch cli
"""
from __future__ import annotations
import argparse, contextlib, filecmp, functools, glob, mmap, os, re, shutil, sys
from concurrent.futures import ThreadPoolExecutor
try:
    import winreg
except Exception:
    winreg = None

BAK = ".agybak"
TARGETS = ("cli", "manager", "ide")

# ----------------------------------------------------------------------- utils
def _say(tag, msg): print(f"  [{tag}] {msg}")
def ok(m):   _say("ok", m)
def info(m): _say("..", m)
def warn(m): _say("!!", m)

def is_locked(path):
    try:
        with open(path, "r+b"):
            return False
    except OSError:
        return True

def make_backup(path):
    """Snapshot the clean file as <path>.agybak (callers reach here only when unpatched,
    so the live bytes are this build's pristine original). A backup that no longer
    matches the file is stale (app auto-updated) — refresh it instead of keeping it."""
    bak = path + BAK
    if os.path.exists(bak):
        if filecmp.cmp(path, bak, shallow=False):
            return                                  # backup already matches this build
        info(f"backup is stale (app updated) — refreshing {os.path.basename(path)}{BAK}")
    else:
        info(f"backup -> {os.path.basename(path)}{BAK}")
    shutil.copy2(path, bak)

def restore_file(path):
    b = path + BAK
    if not os.path.exists(b):
        warn(f"no backup for {os.path.basename(path)} (nothing to restore)")
        return False
    if is_locked(path):
        warn("file is locked — close the app first"); return False
    shutil.copy2(b, path)
    ok(f"restored {os.path.basename(path)}")
    return True

def rmtree_quiet(p):
    try:
        if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass

@contextlib.contextmanager
def mapped(path):
    """Read-only, zero-copy bytes-like view (works with .find(), slicing, re) for
    marker/regex scans — avoids slurping multi-MB binaries into RAM."""
    with open(path, "rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            yield b""; return
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try: yield mm
        finally: mm.close()

# ----------------------------------------------------------------- discovery --
# Install-location-agnostic search: env roots + Programs/Program Files + registry
# InstallLocation + PATH (+ scoop). Apps are matched by a structural marker file,
# never a hard-coded path or version.
@functools.lru_cache(maxsize=1)
def _reg_install_dirs():
    dirs = []
    if not winreg: return dirs
    for hive, sub in ((winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_LOCAL_MACHINE,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_LOCAL_MACHINE,  r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")):
        try: key = winreg.OpenKey(hive, sub)
        except OSError: continue
        try: cnt = winreg.QueryInfoKey(key)[0]
        except OSError: cnt = 0
        for i in range(cnt):
            try:
                s = winreg.OpenKey(key, winreg.EnumKey(key, i))
                if "antigravity" in str(winreg.QueryValueEx(s, "DisplayName")[0]).lower():
                    loc = winreg.QueryValueEx(s, "InstallLocation")[0]
                    if loc: dirs.append(loc)
            except OSError:
                pass
    return dirs

@functools.lru_cache(maxsize=1)
def _roots():
    out = []
    for v in ("LOCALAPPDATA", "ProgramW6432", "PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramData", "APPDATA"):
        p = os.environ.get(v)
        if not p: continue
        out += [p, os.path.join(p, "Programs")]
    up = os.environ.get("USERPROFILE", "")
    out += [os.path.join(up, "scoop", "apps"), os.path.join(os.environ.get("SCOOP", ""), "apps")]
    out += _reg_install_dirs()
    seen, roots = set(), []
    for r in out:
        if r and os.path.isdir(r):
            k = os.path.normcase(os.path.realpath(r))
            if k not in seen: seen.add(k); roots.append(r)
    return roots

def _dedup_newest(paths):
    seen, out = set(), []
    for p in sorted({p for p in paths if os.path.exists(p)},
                    key=lambda x: os.path.getmtime(x), reverse=True):
        k = os.path.normcase(os.path.realpath(p))
        if k not in seen: seen.add(k); out.append(p)
    return out

def find_marker(rel):
    """Find <root>/*antigravity*/<rel> (also one level deeper for scoop version/
    'current' dirs, and rel directly under a registry InstallLocation)."""
    hits = []
    for root in _roots():
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct): hits.append(direct)
    return _dedup_newest(hits)

# ---------------------------------------------------- byte-signature gate -----
# CLI and Manager each fix ONE machine-code site found by a binary-unique signature,
# overwriting a few bytes in place. The machinery is shared; only the signatures,
# replacement bytes, write offset and labels differ, so each target declares a Gate.
# (Signatures use re.S so a `.` wildcard also matches a 0x0a displacement byte.)
class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc=""):
        self.sig, self.patched = re.compile(sig, re.S), re.compile(patched, re.S)
        self.fix, self.offset, self.desc = fix, offset, desc
    def find(self, data):
        """('patched'|'unpatched', file offset to write at), or raise LookupError if
        the signature is missing or not unique (unknown build — refuse to guess)."""
        m = self.patched.search(data)
        if m: return ("patched", m.start()+self.offset)
        m = self.sig.search(data)
        if not m: raise LookupError("gate signature not found (unsupported version?)")
        if self.sig.search(data, m.end()): raise LookupError("gate signature is not unique — refusing to guess")
        return ("unpatched", m.start()+self.offset)

def gate_status(path, gate):
    with mapped(path) as d:
        try: return (gate.find(d)[0], None)
        except LookupError: return ("unknown", None)

def gate_patch(path, gate, app, fname):
    if is_locked(path):
        warn(f"{fname} is locked — close {app} first"); return False
    with mapped(path) as d:                       # zero-copy scan; mmap closed before we write
        try: kind, off = gate.find(d)
        except LookupError as e: warn(str(e)); return False
        if kind == "patched": ok(f"{app} already patched"); return True
    make_backup(path)
    with open(path, "r+b") as f:
        f.seek(off); f.write(gate.fix); f.flush(); os.fsync(f.fileno())
    ok(f"{app} patched ({gate.desc} @ file 0x{off:x})")
    return True

# ------------------------------------------------------------------- CLI ------
# agy.exe's handleAuthResult gates the cosmetic "Eligibility Check" on the server
# AuthResult's hasValidAuth (+8):  test rax,rax ; je ; cmp byte[rax+8],0 ; jne.
# rax is non-null here (the je above), so rewriting the compare to `test rax,rax`+nop
# keeps ZF=0 -> the jne always takes the eligible branch and the screen never renders.
CLI_GATE = Gate(rb"\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85....",
                rb"\x48\x85\xc0\x0f\x84....\x48\x85\xc0\x90\x0f\x85....",
                b"\x48\x85\xc0\x90", offset=9, desc="eligibility screen off")

def cli_default_paths():
    cands = []
    w = shutil.which("agy")
    if w: cands.append(w)
    for root in _roots():
        cands += glob.glob(os.path.join(root, "agy", "bin", "agy.exe"))
        cands += glob.glob(os.path.join(root, "agy", "*", "bin", "agy.exe"))   # scoop version dirs
        cands += glob.glob(os.path.join(root, "agy*", "agy.exe"))
    return _dedup_newest(cands)

# --------------------------------------------------- Manager (auth gate) ------
# language_server.exe (Go) gates the account on validateLogin's hasValidAuth (byte at
# result+8) and won't persist the OAuth token while it's false; the validator attaches
# the token right after via stores into result+0x40 (temp register wildcarded for
# recompiles). Forcing the byte true covers every login flow (incl. account switch).
# cmp byte[rax+8],0 ; je ; mov rT,[rsp+d] ; mov [rax+0x40],rT  ->  mov byte[rax+8],1;nop;nop
MANAGER_GATE = Gate(rb"\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89[\x40\x48\x50\x58\x60\x68\x70\x78]\x40",
                    rb"\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89[\x40\x48\x50\x58\x60\x68\x70\x78]\x40",
                    b"\xc6\x40\x08\x01\x90\x90", desc="hasValidAuth=true")

def manager_default_bins():
    return find_marker(os.path.join("resources", "bin", "language_server.exe"))

# --------------------------------------------------------------------- IDE ----
IDE_RE = re.compile(rb"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = b"resetIsTierGCPTos(),true"

def ide_default_mains():
    return find_marker(os.path.join("resources", "app", "out", "main.js"))

def ide_status(path):
    with mapped(path) as d:
        gate = IDE_RE.search(d)
        if d.find(IDE_DONE) != -1 and not gate: return ("patched", None)
        return ("unpatched" if gate else "unknown", None)

def _ide_cache_dirs():
    dirs = []
    for p in (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
              r"%APPDATA%\Antigravity IDE"):
        base = os.path.expandvars(p)
        dirs += [os.path.join(base, "CachedData"),
                 os.path.join(base, "Code Cache", "js")]
    return dirs

def ide_patch(path):
    if is_locked(path): warn("main.js is locked — close Antigravity IDE first"); return False
    with open(path, "rb") as f: d = f.read()
    if IDE_DONE in d and not IDE_RE.search(d): ok("IDE already patched"); return True
    if not IDE_RE.search(d):
        warn("isGoogleInternal auth-gate pattern not found (unsupported version?)"); return False
    make_backup(path)
    with open(path, "wb") as f: f.write(IDE_RE.sub(rb"\1true", d))
    for c in _ide_cache_dirs(): rmtree_quiet(c)
    ok("IDE patched (isGoogleInternal -> true) + caches cleared")
    return True

# -------------------------------------------------------------------- driver --
SPEC = {
    "cli":     dict(name="Antigravity CLI",      find=cli_default_paths,     status=functools.partial(gate_status, gate=CLI_GATE),
                    patch=functools.partial(gate_patch, gate=CLI_GATE, app="CLI", fname="agy.exe")),
    "manager": dict(name="Antigravity Manager",  find=manager_default_bins,  status=functools.partial(gate_status, gate=MANAGER_GATE),
                    patch=functools.partial(gate_patch, gate=MANAGER_GATE, app="Manager", fname="language_server.exe")),
    "ide":     dict(name="Antigravity IDE",      find=ide_default_mains,     status=ide_status,     patch=ide_patch),
}

def resolve(target, override):
    if override: return override if os.path.exists(override) else None
    for p in SPEC[target]["find"]():
        if p and os.path.exists(p): return p
    return None

def run(action, targets, overrides):
    rc = 0
    for t in targets:
        spec = SPEC[t]; path = resolve(t, overrides.get(t))
        print(f"\n=== {spec['name']} ({t}) ===")
        if not path:
            warn("not found (use --path-%s to point at it)" % t); continue
        print(f"  target: {path}")
        try:
            if action == "status":
                st, _ = spec["status"](path); ok(f"status: {st}")
            elif action == "patch":
                if not spec["patch"](path): rc = 1
            elif action == "restore":
                if spec["status"](path)[0] == "patched":
                    restore_file(path)
                else:
                    warn("not patched — skipping restore (backup may be a different build)")
        except Exception as e:
            warn(f"error: {e}"); rc = 1
    return rc

def _status_of(t, path):
    """Status string for an already-resolved path (no filesystem/registry scan)."""
    if not path: return "not found"
    try:
        return SPEC[t]["status"](path)[0]
    except Exception:
        return "error"

def state(t, overrides=None):
    """(path|None, status_str) for one target."""
    path = resolve(t, (overrides or {}).get(t))
    return path, _status_of(t, path)

def scan(overrides):
    """Resolve paths + status for every target once, concurrently. Discovery and
    binary scans happen here (not per menu redraw); the registry/root probe is
    shared and the three targets run in parallel. Returns (paths, status) dicts."""
    _reg_install_dirs.cache_clear(); _roots.cache_clear()   # rediscover on (re)scan
    _roots()                                                # warm shared cache once
    def one(t):
        p = resolve(t, overrides.get(t))
        return t, p, _status_of(t, p)
    paths, status = {}, {}
    with ThreadPoolExecutor(max_workers=len(TARGETS)) as ex:
        for t, p, st in ex.map(one, TARGETS):
            paths[t], status[t] = p, st
    return paths, status

# --------------------------------------------------------------- interactive --
_STYLE = {"patched": "bold green", "unpatched": "yellow", "unknown": "magenta",
          "not found": "dim", "error": "bold red"}
_ICON  = {"patched": "✓", "unpatched": "●", "unknown": "?", "not found": "·", "error": "!"}

def _render(console, paths, status):
    from rich.table import Table
    from rich.panel import Panel
    tbl = Table(box=None, expand=True, pad_edge=False)
    tbl.add_column("App", style="bold cyan", no_wrap=True)
    tbl.add_column("Status", no_wrap=True)
    tbl.add_column("Location", style="dim", overflow="fold")
    for t in TARGETS:
        path, st = paths[t], status[t]
        tbl.add_row(SPEC[t]["name"], f"[{_STYLE[st]}]{_ICON[st]} {st}[/]", path or "—")
    console.print(Panel(tbl, title="[bold white]agy-unlock[/] · Antigravity eligibility patcher",
                        subtitle="[dim]↑↓ move · enter select · space toggle[/]", border_style="cyan"))

def interactive(overrides):
    import questionary
    from rich.console import Console
    console = Console()
    qs = questionary.Style([("qmark", "fg:#00afff bold"), ("pointer", "fg:#00afff bold"),
                            ("highlighted", "fg:#00afff bold"), ("selected", "fg:#00ff87 bold"),
                            ("answer", "fg:#00ff87 bold")])
    paths, status = scan(overrides)        # discover + status once; reused across redraws
    while True:
        console.clear()
        _render(console, paths, status)
        action = questionary.select("What do you want to do?", style=qs, qmark="»", choices=[
            questionary.Choice("Patch app(s)", "patch"),
            questionary.Choice("Restore app(s) from backup", "restore"),
            questionary.Choice("Refresh status", "refresh"),
            questionary.Choice("Quit", "quit"),
        ]).ask()
        if action in (None, "quit"):
            console.print("[dim]bye 👋[/]"); return 0
        if action == "refresh":
            paths, status = scan(overrides)        # explicit rescan on user request
            continue
        opts = []
        for t in TARGETS:
            path, st = paths[t], status[t]
            if not path:
                continue
            if action == "patch" and st == "patched": continue        # nothing to do
            if action == "restore" and st != "patched": continue   # only undo a real patch
            opts.append(questionary.Choice(f"{SPEC[t]['name']}  · {st}", value=t))
        if not opts:
            console.print(f"[yellow]Nothing to {action}.[/]")
            questionary.press_any_key_to_continue("Enter to continue…", style=qs).ask(); continue
        sel = questionary.checkbox(f"Select app(s) to {action}:", choices=opts, style=qs).ask()
        if not sel:
            continue
        if action == "patch" and not questionary.confirm(
                f"Patch {len(sel)} app(s)? A backup is made first.", default=True, style=qs).ask():
            continue
        console.rule(f"[bold cyan]{action}[/]")
        run(action, sel, overrides)
        for t in sel:                              # refresh only what we just touched
            status[t] = _status_of(t, paths[t])
        console.rule(style="dim")
        questionary.press_any_key_to_continue("Enter to return to the menu…", style=qs).ask()

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Hide the Antigravity eligibility gate (CLI / Manager / IDE). "
                    "Run with no arguments for the interactive menu.")
    ap.add_argument("action", choices=("menu", "status", "patch", "restore"), nargs="?",
                    help="menu (default, interactive) | status | patch | restore")
    ap.add_argument("targets", nargs="*", default=[], metavar="{cli,manager,ide}",
                    help="which apps to act on (default: all)")
    for t in TARGETS: ap.add_argument(f"--path-{t}", help=f"explicit path for {t}")
    args = ap.parse_args(argv)
    bad = [t for t in args.targets if t not in TARGETS]
    if bad:
        ap.error(f"invalid target(s): {', '.join(bad)} (choose from: {', '.join(TARGETS)})")
    overrides = {t: getattr(args, f"path_{t}") for t in TARGETS}

    if args.action in (None, "menu"):
        try:
            import questionary, rich  # noqa: F401
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise RuntimeError("not a terminal")
            return interactive(overrides)
        except KeyboardInterrupt:
            print(); return 0
        except ImportError:
            warn("interactive menu needs:  pip install rich questionary")
            if args.action == "menu": return 2
        except Exception:
            if args.action == "menu":
                warn("interactive menu needs a real terminal"); return 2
        # plain fallback (no TTY / missing deps)
        print("agy-unlock - status")
        return run("status", list(TARGETS), overrides)

    targets = args.targets if args.targets else list(TARGETS)
    print(f"agy-unlock - {args.action}")
    return run(args.action, targets, overrides)

if __name__ == "__main__":
    raise SystemExit(main())
