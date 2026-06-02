#!/usr/bin/env python3
"""
agy-unlock — hide the cosmetic / non-blocking "not available in your location"
eligibility gate in the three Antigravity apps on Windows:

  * cli      Antigravity CLI         (agy.exe, Go binary)        -> NOP the startup banner
  * manager  Antigravity (Manager)   (Electron, app.asar)        -> neutralize GetAuthStatus verdict
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
import argparse, glob, hashlib, json, os, shutil, struct, sys
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
    if not os.path.exists(path + BAK):
        shutil.copy2(path, path + BAK)
        info(f"backup -> {os.path.basename(path)}{BAK}")

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

# ----------------------------------------------------------------- discovery --
# Generic, install-location-agnostic search: standard env roots + per-user/
# machine "Programs"/Program Files + Windows registry InstallLocation + PATH
# (+ scoop if present). Apps are matched by a STRUCTURAL marker file, never by
# a hard-coded path or version.
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

# --------------------------------------------------------------- PE (cli) -----
class PE:
    def __init__(self, data: bytes):
        if data[:2] != b"MZ": raise ValueError("not a PE")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e+4] != b"PE\0\0": raise ValueError("no PE sig")
        nsec = struct.unpack_from("<H", data, e+6)[0]
        optsz = struct.unpack_from("<H", data, e+20)[0]
        opt = e+24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B: raise ValueError("not PE32+")
        self.base = struct.unpack_from("<Q", data, opt+24)[0]
        self.secs = []
        sh = opt + optsz
        for i in range(nsec):
            o = sh + 40*i
            name = data[o:o+8].rstrip(b"\0").decode("latin1")
            vsz, va, rsz, rp = struct.unpack_from("<IIII", data, o+8)
            self.secs.append((name, rp, rsz, va, vsz))
    def off2va(self, off):
        for _n, rp, rsz, va, _vs in self.secs:
            if rp <= off < rp+rsz: return self.base+va+(off-rp)
    def text(self):
        for s in self.secs:
            if s[0] == ".text": return s
        raise ValueError("no .text")

# ------------------------------------------------------------------- CLI ------
CLI_MARKER = b"Eligibility Check"
NOP5 = b"\x90"*5

def cli_default_paths():
    cands = []
    w = shutil.which("agy")
    if w: cands.append(w)
    for root in _roots():
        cands += glob.glob(os.path.join(root, "agy", "bin", "agy.exe"))
        cands += glob.glob(os.path.join(root, "agy", "*", "bin", "agy.exe"))   # scoop version dirs
        cands += glob.glob(os.path.join(root, "agy*", "agy.exe"))
    return _dedup_newest(cands)

def cli_find_call(data):
    """Return file offset of the `call` that emits the eligibility section, or
    ('patched', off) / raise. Version-robust: locate the unique marker string,
    the RIP-relative LEA that references it, then the first `call rel32` after."""
    pe = PE(data)
    first = data.find(CLI_MARKER)
    if first < 0 or data.find(CLI_MARKER, first+1) != -1:
        raise LookupError("marker string missing or not unique")
    mva = pe.off2va(first)
    _n, traw, trsz, tva, _vs = pe.text()
    tb = data[traw:traw+trsz]; tva0 = pe.base+tva
    lea = None; i = 0
    while i < len(tb)-7:
        if tb[i] in (0x48, 0x4C) and tb[i+1] == 0x8D and (tb[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", tb, i+3)[0]
            if tva0+i+7+disp == mva:
                if lea is not None: raise LookupError("multiple LEA refs")
                lea = traw+i; i += 7; continue
        i += 1
    if lea is None: raise LookupError("no LEA ref to marker")
    for j in range(lea+7, lea+7+0x100):
        if data[j:j+5] == NOP5: return ("patched", j)
        if data[j] == 0xE8:
            tgt = pe.off2va(j) + 5 + struct.unpack_from("<i", data, j+1)[0]
            if tva0 <= tgt < tva0+trsz: return ("call", j)
    raise LookupError("no call after render site")

def cli_status(path):
    data = open(path, "rb").read()
    kind, off = cli_find_call(data)
    return ("patched" if kind == "patched" else "unpatched", off)

def cli_patch(path):
    if is_locked(path): warn("agy.exe is locked — close the CLI first"); return False
    data = open(path, "rb").read()
    kind, off = cli_find_call(data)
    if kind == "patched": ok("CLI already patched"); return True
    make_backup(path)
    with open(path, "r+b") as f:
        f.seek(off); f.write(NOP5); f.flush(); os.fsync(f.fileno())
    ok(f"CLI patched (NOP @ file 0x{off:x})")
    return True

# ----------------------------------------------------------------- asar -------
def asar_load(path):
    raw = open(path, "rb").read()
    json_size = struct.unpack_from("<I", raw, 12)[0]
    header = json.loads(raw[16:16+json_size].decode("utf-8"))
    base = 8 + struct.unpack_from("<I", raw, 4)[0]
    return raw, header, base

def asar_get(header, parts):
    node = header
    for p in parts: node = node["files"][p]
    return node

def asar_save(path, header, base, raw, mods):
    files = []
    def walk(node, pref):
        for name, meta in node.get("files", {}).items():
            p = pref+(name,)
            if "files" in meta: walk(meta, p)
            else: files.append((meta, p))
    walk(header, ())
    blob = bytearray()
    for meta, p in files:
        if meta.get("unpacked"): continue
        if p in mods:
            content = mods[p]
        else:
            off = int(meta["offset"]); sz = meta["size"]
            content = raw[base+off:base+off+sz]
        meta["offset"] = str(len(blob)); meta["size"] = len(content)
        integ = meta.get("integrity")
        if integ:
            bs = integ.get("blockSize", 4*1024*1024)
            integ["hash"] = hashlib.sha256(content).hexdigest()
            integ["blocks"] = [hashlib.sha256(content[i:i+bs]).hexdigest()
                               for i in range(0, len(content), bs)] or [hashlib.sha256(b"").hexdigest()]
        blob += content
    js = json.dumps(header, separators=(",", ":")).encode("utf-8")
    pad = (4 - len(js) % 4) % 4
    aligned = len(js) + pad
    head = struct.pack("<IIII", 4, 8+aligned, 4+aligned, len(js)) + js + b"\0"*pad
    with open(path, "wb") as f:
        f.write(head); f.write(bytes(blob))

# ----------------------------------------------------------------- Manager ----
# Injected (main world) hook: intercept GetAuthStatus (grpc-web+json), de-frame,
# set authResult.hasValidAuth=true and drop the failure_details oneof, re-frame.
MANAGER_HOOK = (
"(function(){if(window.__agyAuth)return;window.__agyAuth=1;"
"var td=new TextDecoder(),te=new TextEncoder();"
"var rd=function(b,i){return b[i]*16777216+b[i+1]*65536+b[i+2]*256+b[i+3];};"
'var FK=["ineligible","verificationRequired","tosViolation","generalError","projectRequired","headlessAuthRequired","uiMessage"];'
'function fix(o){var c=false,ar=o&&o.authResult;if(ar&&typeof ar==="object"&&!Array.isArray(ar)){FK.forEach(function(k){if(k in ar){delete ar[k];c=true;}});if(ar.hasValidAuth!==true){ar.hasValidAuth=true;c=true;}}return c;}'
"var OF=window.fetch;window.fetch=function(input){"
'var url=(typeof input==="string")?input:(input&&input.url)||"";'
'if(url.indexOf("GetAuthStatus")===-1)return OF.apply(this,arguments);'
"return OF.apply(this,arguments).then(function(resp){return resp.clone().arrayBuffer().then(function(buf){try{"
'var ct=resp.headers.get("content-type")||"";if(ct.indexOf("grpc-web")===-1)return resp;'
"var b=new Uint8Array(buf),fr=[],i=0,ch=false;"
"while(i+5<=b.length){var fl=b[i],L=rd(b,i+1);fr.push({flag:fl,payload:b.subarray(i+5,i+5+L)});i+=5+L;}"
"fr.forEach(function(f){if((f.flag&0x80)===0){try{var o=JSON.parse(td.decode(f.payload));if(fix(o)){f.payload=te.encode(JSON.stringify(o));ch=true;}}catch(e){}}});"
"if(!ch)return resp;var t=0;fr.forEach(function(f){t+=5+f.payload.length;});var out=new Uint8Array(t),p=0;"
"fr.forEach(function(f){var L=f.payload.length;out[p]=f.flag;out[p+1]=(L>>>24)&255;out[p+2]=(L>>>16)&255;out[p+3]=(L>>>8)&255;out[p+4]=L&255;out.set(f.payload,p+5);p+=5+L;});"
'var h=new Headers(resp.headers);h.delete("content-length");'
"return new Response(out,{status:resp.status,statusText:resp.statusText,headers:h});"
"}catch(e){return resp;}}).catch(function(){return resp;});});};})();"
)
MANAGER_INJECT = ('\n// agy-unlock: neutralize GetAuthStatus ineligible verdict\n'
                  'try{require("electron").webFrame.executeJavaScript(' + json.dumps(MANAGER_HOOK) + ');}catch(e){}\n')

def manager_default_asars():
    return find_marker(os.path.join("resources", "app.asar"))

def manager_status(path):
    raw = open(path, "rb").read()
    return ("patched" if b"__agyAuth" in raw else "unpatched", None)

def manager_patch(path):
    if is_locked(path): warn("app.asar is locked — close Antigravity (Manager) first"); return False
    raw, header, base = asar_load(path)
    if b"__agyAuth" in raw: ok("Manager already patched"); return True
    try:
        pre = asar_get(header, ("dist", "preload.js"))
    except KeyError:
        warn("dist/preload.js not found in app.asar"); return False
    off = int(pre["offset"]); sz = pre["size"]
    content = raw[base+off:base+off+sz]
    make_backup(path)
    asar_save(path, header, base, raw, {("dist", "preload.js"): content + MANAGER_INJECT.encode("utf-8")})
    _clear_caches(os.path.expandvars(r"%APPDATA%\Antigravity"))
    ok("Manager patched (preload hook injected, asar repacked)")
    return True

# --------------------------------------------------------------------- IDE ----
import re
IDE_RE = re.compile(rb"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = b"resetIsTierGCPTos(),true"

def ide_default_mains():
    return find_marker(os.path.join("resources", "app", "out", "main.js"))

def ide_status(path):
    d = open(path, "rb").read()
    if IDE_DONE in d and not IDE_RE.search(d): return ("patched", None)
    return ("unpatched" if IDE_RE.search(d) else "unknown", None)

def _ide_cache_dirs():
    dirs = []
    for p in (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
              r"%APPDATA%\Antigravity IDE"):
        base = os.path.expandvars(p)
        dirs += [os.path.join(base, "CachedData"),
                 os.path.join(base, "Code Cache", "js")]
    return dirs

def _clear_caches(userdata_root):
    for sub in ("CachedData", os.path.join("Code Cache", "js")):
        rmtree_quiet(os.path.join(userdata_root, sub))

def ide_patch(path):
    if is_locked(path): warn("main.js is locked — close Antigravity IDE first"); return False
    d = open(path, "rb").read()
    if IDE_DONE in d and not IDE_RE.search(d): ok("IDE already patched"); return True
    if not IDE_RE.search(d):
        warn("isGoogleInternal auth-gate pattern not found (unsupported version?)"); return False
    make_backup(path)
    open(path, "wb").write(IDE_RE.sub(rb"\1true", d))
    for c in _ide_cache_dirs(): rmtree_quiet(c)
    ok("IDE patched (isGoogleInternal -> true) + caches cleared")
    return True

# -------------------------------------------------------------------- driver --
SPEC = {
    "cli":     dict(name="Antigravity CLI",      find=cli_default_paths,     status=cli_status,     patch=cli_patch),
    "manager": dict(name="Antigravity Manager",  find=manager_default_asars, status=manager_status, patch=manager_patch),
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
                restore_file(path)
        except Exception as e:
            warn(f"error: {e}"); rc = 1
    return rc

def state(t, overrides=None):
    """(path|None, status_str) for one target."""
    path = resolve(t, (overrides or {}).get(t))
    if not path: return None, "not found"
    try:
        return path, SPEC[t]["status"](path)[0]
    except Exception:
        return path, "error"

# --------------------------------------------------------------- interactive --
_STYLE = {"patched": "bold green", "unpatched": "yellow", "unknown": "magenta",
          "not found": "dim", "error": "bold red"}
_ICON  = {"patched": "✓", "unpatched": "●", "unknown": "?", "not found": "·", "error": "!"}

def _render(console, overrides):
    from rich.table import Table
    from rich.panel import Panel
    tbl = Table(box=None, expand=True, pad_edge=False)
    tbl.add_column("App", style="bold cyan", no_wrap=True)
    tbl.add_column("Status", no_wrap=True)
    tbl.add_column("Location", style="dim", overflow="fold")
    for t in TARGETS:
        path, st = state(t, overrides)
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
    while True:
        console.clear()
        _render(console, overrides)
        action = questionary.select("What do you want to do?", style=qs, qmark="»", choices=[
            questionary.Choice("Patch app(s)", "patch"),
            questionary.Choice("Restore app(s) from backup", "restore"),
            questionary.Choice("Refresh status", "refresh"),
            questionary.Choice("Quit", "quit"),
        ]).ask()
        if action in (None, "quit"):
            console.print("[dim]bye 👋[/]"); return 0
        if action == "refresh":
            continue
        opts = []
        for t in TARGETS:
            path, st = state(t, overrides)
            if not path:
                continue
            if action == "patch" and st == "patched": continue        # nothing to do
            if action == "restore" and not os.path.exists(path + BAK): continue
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
