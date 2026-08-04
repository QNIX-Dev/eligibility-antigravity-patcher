#!/usr/bin/env python3
"""Patch Antigravity eligibility gates and manage Windows login profiles."""
from __future__ import annotations
import argparse, base64, contextlib, filecmp, functools, glob, json, mmap, os, re, shutil, sqlite3, struct, sys, time
from concurrent.futures import ThreadPoolExecutor
try:
    import winreg
except Exception:
    winreg = None

BAK = ".agybak"
TARGETS = ("cli", "manager", "ide")

# Utilities
def _say(tag, msg): print(f"  [{tag}] {msg}")
def ok(m):   _say("ok", m)
def info(m): _say("..", m)
def warn(m): _say("!!", m)

def _bin(name):
    return name + (".exe" if os.name == "nt" else "")

def is_locked(path):
    try:
        with open(path, "r+b"):
            return False
    except OSError:
        return True

def make_backup(path):
    """Create or refresh a verified clean backup."""
    bak = path + BAK
    if os.path.exists(bak):
        if filecmp.cmp(path, bak, shallow=False):
            return bak
        info(f"backup is stale (app updated) — refreshing {os.path.basename(path)}{BAK}")
    else:
        info(f"backup -> {os.path.basename(path)}{BAK}")
    shutil.copy2(path, bak)
    if not filecmp.cmp(path, bak, shallow=False):
        raise OSError("backup verification failed")
    return bak

def restore_file(path, status=None):
    b = path + BAK
    if not os.path.exists(b):
        warn(f"no backup for {os.path.basename(path)} (nothing to restore)")
        return False
    if is_locked(path):
        warn("file is locked — close the app first"); return False
    if status:
        try:
            if status(b)[0] != "unpatched":
                warn("backup is not a recognized clean build — refusing to restore")
                return False
        except Exception as e:
            warn(f"couldn't validate backup: {e}"); return False
    shutil.copy2(b, path)
    if status and status(path)[0] != "unpatched":
        warn("restore verification failed")
        return False
    ok(f"restored {os.path.basename(path)}")
    return True

def rmtree_quiet(p):
    try:
        if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass

@contextlib.contextmanager
def mapped(path):
    """Yield a read-only mmap."""
    with open(path, "rb") as f:
        if os.fstat(f.fileno()).st_size == 0:
            yield b""; return
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try: yield mm
        finally: mm.close()

def _read_exact(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError("truncated executable header")
    return data

def _normalized_ranges(ranges, file_size):
    clean = []
    for start, end in ranges:
        start, end = max(0, start), min(file_size, end)
        if start < end: clean.append((start, end))
    out = []
    for start, end in sorted(clean):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return tuple(out)

def _pe_executable_ranges(f, file_size):
    pe = struct.unpack("<I", _read_exact(f, 0x3c, 4))[0]
    if _read_exact(f, pe, 4) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = _read_exact(f, pe + 4, 20)
    section_count = struct.unpack_from("<H", coff, 2)[0]
    optional_size = struct.unpack_from("<H", coff, 16)[0]
    section_table = pe + 24 + optional_size
    ranges = []
    for i in range(section_count):
        section = _read_exact(f, section_table + i * 40, 40)
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        characteristics = struct.unpack_from("<I", section, 36)[0]
        if characteristics & 0x20000000:
            ranges.append((raw_offset, raw_offset + raw_size))
    return _normalized_ranges(ranges, file_size)

def _elf_executable_ranges(f, file_size):
    ident = _read_exact(f, 0, 16)
    elf_class, data_order = ident[4], ident[5]
    endian = "<" if data_order == 1 else ">" if data_order == 2 else None
    if endian is None:
        raise ValueError("unknown ELF byte order")
    if elf_class == 2:
        header = _read_exact(f, 0, 64)
        phoff = struct.unpack_from(endian + "Q", header, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 54)
        layout = (0, 4, 8, 32, "I", "I", "Q", "Q")
    elif elf_class == 1:
        header = _read_exact(f, 0, 52)
        phoff = struct.unpack_from(endian + "I", header, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 42)
        layout = (0, 24, 4, 16, "I", "I", "I", "I")
    else:
        raise ValueError("unknown ELF class")
    type_off, flags_off, file_off, size_off, type_fmt, flags_fmt, off_fmt, size_fmt = layout
    ranges = []
    for i in range(phnum):
        entry = _read_exact(f, phoff + i * phentsize, phentsize)
        p_type = struct.unpack_from(endian + type_fmt, entry, type_off)[0]
        flags = struct.unpack_from(endian + flags_fmt, entry, flags_off)[0]
        offset = struct.unpack_from(endian + off_fmt, entry, file_off)[0]
        size = struct.unpack_from(endian + size_fmt, entry, size_off)[0]
        if p_type == 1 and flags & 1:
            ranges.append((offset, offset + size))
    return _normalized_ranges(ranges, file_size)

def _macho_slice_ranges(f, file_size, base, slice_size):
    magic = _read_exact(f, base, 4)
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O slice")
    header = _read_exact(f, base, 32)
    command_count = struct.unpack_from(endian + "I", header, 16)[0]
    pos, ranges = base + 32, []
    for _ in range(command_count):
        command_header = _read_exact(f, pos, 8)
        command, command_size = struct.unpack(endian + "II", command_header)
        if command_size < 8 or pos + command_size > base + slice_size:
            raise ValueError("invalid Mach-O load command")
        if command == 0x19:
            segment = _read_exact(f, pos, command_size)
            section_count = struct.unpack_from(endian + "I", segment, 64)[0]
            if 72 + section_count * 80 > command_size:
                raise ValueError("invalid Mach-O section table")
            section_pos = 72
            for _ in range(section_count):
                section = segment[section_pos:section_pos + 80]
                section_name = section[:16].split(b"\0", 1)[0]
                segment_name = section[16:32].split(b"\0", 1)[0]
                size = struct.unpack_from(endian + "Q", section, 40)[0]
                offset = struct.unpack_from(endian + "I", section, 48)[0]
                flags = struct.unpack_from(endian + "I", section, 64)[0]
                is_code = ((segment_name, section_name) == (b"__TEXT", b"__text") or
                           flags & (0x80000000 | 0x00000400))
                if is_code:
                    ranges.append((base + offset, base + offset + size))
                section_pos += 80
        pos += command_size
    return _normalized_ranges(ranges, file_size)

def _macho_executable_ranges(f, file_size):
    magic = _read_exact(f, 0, 4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return _macho_slice_ranges(f, file_size, 0, file_size)
    fat = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),  b"\xbf\xba\xfe\xca": ("<", True),
    }.get(magic)
    if not fat:
        raise ValueError("unsupported Mach-O header")
    endian, is_64 = fat
    count = struct.unpack(endian + "I", _read_exact(f, 4, 4))[0]
    entry_size = 32 if is_64 else 20
    ranges = []
    for i in range(count):
        entry = _read_exact(f, 8 + i * entry_size, entry_size)
        if is_64:
            offset, size = struct.unpack_from(endian + "QQ", entry, 8)
        else:
            offset, size = struct.unpack_from(endian + "II", entry, 8)
        ranges += _macho_slice_ranges(f, file_size, offset, size)
    return _normalized_ranges(ranges, file_size)

def executable_ranges(path):
    """Return executable file ranges for PE, ELF, or Mach-O."""
    with open(path, "rb") as f:
        file_size = os.fstat(f.fileno()).st_size
        magic = _read_exact(f, 0, min(4, file_size))
        if magic[:2] == b"MZ":
            ranges = _pe_executable_ranges(f, file_size)
        elif magic == b"\x7fELF":
            ranges = _elf_executable_ranges(f, file_size)
        else:
            ranges = _macho_executable_ranges(f, file_size)
    if not ranges:
        raise ValueError("no executable code ranges found")
    return ranges

# Discovery
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
    """Find a marker below known Windows install roots."""
    hits = []
    for root in _roots():
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct): hits.append(direct)
    return _dedup_newest(hits)

def _posix_install_roots(*launchers):
    home = os.path.expanduser("~")
    roots = ["/opt", "/usr/share", "/usr/lib", "/usr/local/share", "/usr/local/lib",
             "/Applications",
             os.path.join(home, ".local", "share"),
             os.path.join(home, "Applications"),
             os.path.join(home, "Downloads"), home]
    for launcher in launchers:
        w = shutil.which(launcher)
        if w: roots.append(os.path.dirname(os.path.realpath(w)))
    return roots

def _posix_find(rel, *launchers):
    """Find a marker below known POSIX install roots."""
    hits = []
    for root in _posix_install_roots(*launchers):
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct): hits.append(direct)
    return _dedup_newest(hits)

# Binary gates; re.S lets wildcards match every displacement byte.
class SignatureNotFound(LookupError):
    pass

class SignatureAmbiguous(LookupError):
    pass

def _unique_match(pattern, data, ranges, label):
    found = None
    for start, end in ranges:
        pos = start
        while pos < end:
            match = pattern.search(data, pos, end)
            if not match:
                break
            if found is not None:
                raise SignatureAmbiguous(f"{label} signature is not unique — refusing to guess")
            found = match
            pos = max(match.end(), match.start() + 1)
    return found

class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc=""):
        self.sig, self.patched = re.compile(sig, re.S), re.compile(patched, re.S)
        self.fix, self.offset, self.desc = fix, offset, desc
    def find(self, data, ranges=None):
        """Return state and write offset for one unambiguous signature."""
        search_ranges = ranges or ((0, len(data)),)
        original = _unique_match(self.sig, data, search_ranges, "unpatched gate")
        patched = _unique_match(self.patched, data, search_ranges, "patched gate")
        if original and patched:
            raise SignatureAmbiguous("both patched and unpatched gate signatures are present")
        if patched:
            return ("patched", patched.start() + self.offset)
        if original:
            return ("unpatched", original.start() + self.offset)
        raise SignatureNotFound("gate signature not found (unsupported version?)")
    def resolve(self, data, ranges=None):
        kind, off = self.find(data, ranges)
        return kind, off, self

class MultiGate:
    """Select one architecture-specific gate."""
    def __init__(self, *gates, desc=""):
        self.gates, self.desc = gates, desc
    def resolve(self, data, ranges=None):
        matches = []
        for g in self.gates:
            try:
                matches.append(g.resolve(data, ranges))
            except SignatureNotFound:
                pass
        if len(matches) > 1:
            raise SignatureAmbiguous("multiple architecture gate signatures matched")
        if matches:
            return matches[0]
        raise SignatureNotFound("no architecture gate signature matched (unsupported version?)")

def gate_status(path, gate):
    try:
        ranges = executable_ranges(path)
        with mapped(path) as d:
            return (gate.resolve(d, ranges)[0], None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)

def gate_patch(path, gate, app, fname):
    if is_locked(path):
        warn(f"{fname} is locked — close {app} first"); return False
    try:
        ranges = executable_ranges(path)
        with mapped(path) as d:
            kind, off, g = gate.resolve(d, ranges)
    except (LookupError, OSError, ValueError) as e:
        warn(str(e)); return False
    if kind == "patched":
        ok(f"{app} already patched"); return True
    bak = make_backup(path)
    try:
        if not filecmp.cmp(path, bak, shallow=False):
            raise OSError("target changed after backup")
        ranges = executable_ranges(path)
        with open(path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                current_kind, current_off, current_gate = gate.resolve(mm, ranges)
            finally:
                mm.close()
            if current_kind != "unpatched" or current_off != off or current_gate is not g:
                raise OSError("target changed before patch write")
            f.seek(off); f.write(g.fix); f.flush(); os.fsync(f.fileno())
        ranges = executable_ranges(path)
        with mapped(path) as d:
            final_kind, final_off, final_gate = gate.resolve(d, ranges)
        if final_kind != "patched" or final_off != off or final_gate is not g:
            raise OSError("post-write signature verification failed")
    except Exception as e:
        try:
            shutil.copy2(bak, path)
            rolled_back = filecmp.cmp(path, bak, shallow=False)
        except Exception:
            rolled_back = False
        warn(f"{app} patch failed: {e}")
        warn("original restored from backup" if rolled_back else
             f"automatic rollback failed — restore {os.path.basename(bak)} manually")
        return False
    ok(f"{app} patched ({g.desc} @ file 0x{off:x})")
    return True

# CLI eligibility screen
# x64:
#   test rax,rax ; je ; cmp byte[rax+8],0 ; jne eligible ; call failure builder
# Repeating the non-null test keeps ZF=0, so jne always selects eligible.
CLI_GATE_X64 = Gate(
    rb"\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85...."
    rb"\xe8....\x48\x89\x84\x24\x80\x00\x00\x00\x48\x89\x5c\x24\x50"
    rb"\x48\x89\x4c\x24\x70",
    rb"\x48\x85\xc0\x0f\x84....\x48\x85\xc0\x90\x0f\x85...."
    rb"\xe8....\x48\x89\x84\x24\x80\x00\x00\x00\x48\x89\x5c\x24\x50"
    rb"\x48\x89\x4c\x24\x70",
    b"\x48\x85\xc0\x90", offset=9, desc="eligibility screen off (x64)")

# arm64:
#   cbnz x1,error ; cbz x0,eligible ; ldrb w1,[x0,#8] ; tbnz w1,#0,eligible
#   bl failure builder
# Loading 1 instead makes tbnz always select eligible.
CLI_GATE_ARM64 = Gate(
    rb"...\xb5...\xb4\x01\x20\x40\x39...\x37...\x97"
    rb"\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9",
    rb"...\xb5...\xb4\x21\x00\x80\x52...\x37...\x97"
    rb"\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9",
    b"\x21\x00\x80\x52", offset=8, desc="eligibility screen off (arm64)")

CLI_GATE = MultiGate(CLI_GATE_X64, CLI_GATE_ARM64, desc="eligibility screen off")

def cli_default_paths():
    cands = []
    w = shutil.which("agy")
    if w:
        base, ext = os.path.splitext(w); cands.append(base + ext.lower())
    if os.name == "nt":
        for root in _roots():
            cands += glob.glob(os.path.join(root, "agy", "bin", "agy.exe"))
            cands += glob.glob(os.path.join(root, "agy", "*", "bin", "agy.exe"))
            cands += glob.glob(os.path.join(root, "agy*", "agy.exe"))
    else:
        home = os.path.expanduser("~")
        cands += [os.path.join(d, "agy") for d in
                  (os.path.join(home, ".local", "bin"), os.path.join(home, "bin"),
                   "/usr/local/bin", "/usr/bin", "/opt/homebrew/bin")]
    return _dedup_newest(cands)

# Manager auth result
# x64: force hasValidAuth and fall through to token attachment.
# cmp byte[rax+8],0 ; je short  ->  mov byte[rax+8],1 ; nop*2
MANAGER_GATE_X64 = Gate(rb"\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89.\x60",
                        rb"\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89.\x60",
                        b"\xc6\x40\x08\x01\x90\x90", desc="hasValidAuth=true")

# arm64: force hasValidAuth and remove the token-attachment branch.
#   ldrb w3,[x0,#8] ; tbz w3,#0,skip  ->  mov w3,#1 ; strb w3,[x0,#8]
# The branch displacement spans the low byte, so accept every encoding that keeps
# Rt=w3. Builds use either one or two setup instructions before the token stp.
_ARM64_TBZ_W3_BIT0 = rb"[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36"
_ARM64_TOKEN_SETUP = rb"(?:....){1,2}\x03\x10\x06\xa9"
MANAGER_GATE_ARM64 = Gate(rb"\x03\x20\x40\x39" + _ARM64_TBZ_W3_BIT0 + _ARM64_TOKEN_SETUP,
                          rb"\x23\x00\x80\x52\x03\x20\x00\x39" + _ARM64_TOKEN_SETUP,
                          b"\x23\x00\x80\x52\x03\x20\x00\x39", desc="hasValidAuth=true (arm64)")

MANAGER_GATE = MultiGate(MANAGER_GATE_X64, MANAGER_GATE_ARM64, desc="hasValidAuth=true")

def manager_default_bins():
    if os.name == "nt":
        return find_marker(os.path.join("resources", "bin", "language_server.exe"))
    rel = (os.path.join("Contents", "Resources", "bin", "language_server") if sys.platform == "darwin"
           else os.path.join("resources", "bin", "language_server"))
    return _posix_find(rel, "antigravity")

# IDE
IDE_RE = re.compile(rb"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = b"resetIsTierGCPTos(),true"
IDE_DONE_RE = re.compile(re.escape(IDE_DONE))

def ide_default_mains():
    if os.name == "nt":
        return find_marker(os.path.join("resources", "app", "out", "main.js"))
    rel = (os.path.join("Contents", "Resources", "app", "out", "main.js") if sys.platform == "darwin"
           else os.path.join("resources", "app", "out", "main.js"))
    return _posix_find(rel, "antigravity-ide", "antigravity")

def _ide_gate_state(data):
    ranges = ((0, len(data)),)
    original = _unique_match(IDE_RE, data, ranges, "unpatched IDE gate")
    patched = _unique_match(IDE_DONE_RE, data, ranges, "patched IDE gate")
    if original and patched:
        raise SignatureAmbiguous("both patched and unpatched IDE gates are present")
    if original:
        return "unpatched"
    if patched:
        return "patched"
    raise SignatureNotFound("IDE auth-gate pattern not found (unsupported version?)")

def ide_status(path):
    try:
        with mapped(path) as d:
            return (_ide_gate_state(d), None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)

def _ide_cache_dirs():
    """Return JavaScript cache directories invalidated by the patch."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        bases = [os.path.expandvars(p) for p in
                 (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
                  r"%APPDATA%\Antigravity IDE")]
    elif sys.platform == "darwin":
        bases = [os.path.join(home, "Library", "Application Support", "Antigravity IDE")]
    else:
        cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        bases = [os.path.join(cfg, "Antigravity IDE")]
    dirs = []
    for base in bases:
        dirs += [os.path.join(base, "CachedData"),
                 os.path.join(base, "Code Cache", "js")]
    return dirs

def ide_patch(path):
    if is_locked(path): warn("main.js is locked — close Antigravity IDE first"); return False
    with open(path, "rb") as f: d = f.read()
    try:
        kind = _ide_gate_state(d)
    except LookupError as e:
        warn(str(e)); return False
    if kind == "patched":
        ok("IDE already patched"); return True
    bak = make_backup(path)
    try:
        with open(path, "rb") as f:
            current = f.read()
        if current != d or _ide_gate_state(current) != "unpatched":
            raise OSError("target changed before patch write")
        patched, count = IDE_RE.subn(rb"\1true", current, count=1)
        if count != 1:
            raise OSError(f"expected one IDE gate replacement, got {count}")
        with open(path, "wb") as f:
            f.write(patched); f.flush(); os.fsync(f.fileno())
        with mapped(path) as verified:
            if _ide_gate_state(verified) != "patched":
                raise OSError("post-write IDE signature verification failed")
    except Exception as e:
        try:
            shutil.copy2(bak, path)
            rolled_back = filecmp.cmp(path, bak, shallow=False)
        except Exception:
            rolled_back = False
        warn(f"IDE patch failed: {e}")
        warn("original restored from backup" if rolled_back else
             f"automatic rollback failed — restore {os.path.basename(bak)} manually")
        return False
    for c in _ide_cache_dirs(): rmtree_quiet(c)
    ok("IDE patched (isGoogleInternal -> true) + caches cleared")
    return True

# Accounts
# Live logins remain opaque: CLI/Manager use Credential Manager; IDE uses state.vscdb.
ACCT_PREFIX = "agy-manager:account:"
CRED_TARGET = "gemini:antigravity"
CRED_USER   = "antigravity"
IDE_KEYS = ("antigravityUnifiedStateSync.oauthToken",
            "antigravityUnifiedStateSync.userStatus",
            "antigravityUnifiedStateSync.profileUrl",
            "antigravityUnifiedStateSync.modelCredits")

def _advapi():
    """Bind the Windows Credential API."""
    import ctypes
    from ctypes import wintypes
    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_char)), ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    PCRED = ctypes.POINTER(CREDENTIAL)
    a.CredReadW.argtypes  = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCRED)]
    a.CredWriteW.argtypes = [PCRED, wintypes.DWORD]
    a.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    a.CredEnumerateW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.POINTER(PCRED))]
    a.CredFree.argtypes = [ctypes.c_void_p]; a.CredFree.restype = None
    for fn in (a.CredReadW, a.CredWriteW, a.CredDeleteW, a.CredEnumerateW): fn.restype = wintypes.BOOL
    return ctypes, wintypes, a, CREDENTIAL, PCRED

def cred_read(target):
    ctypes, wintypes, a, CRED, PCRED = _advapi()
    p = PCRED()
    if not a.CredReadW(target, 1, 0, ctypes.byref(p)):
        return None
    try:    return ctypes.string_at(p.contents.CredentialBlob, p.contents.CredentialBlobSize)
    finally: a.CredFree(p)

def cred_write(target, blob, user):
    ctypes, wintypes, a, CRED, PCRED = _advapi()
    buf = ctypes.create_string_buffer(blob, len(blob))
    c = CRED(); c.Type = 1; c.TargetName = target; c.UserName = user
    c.CredentialBlobSize = len(blob)
    c.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
    c.Persist = 2
    if not a.CredWriteW(ctypes.byref(c), 0):
        raise OSError(f"CredWrite failed (err {ctypes.get_last_error()})")

def cred_delete(target):
    ctypes, wintypes, a, CRED, PCRED = _advapi()
    return bool(a.CredDeleteW(target, 1, 0))

def cred_enum(prefix):
    ctypes, wintypes, a, CRED, PCRED = _advapi()
    n = wintypes.DWORD(); arr = ctypes.POINTER(PCRED)()
    if not a.CredEnumerateW(prefix + "*", 0, ctypes.byref(n), ctypes.byref(arr)):
        return []
    try:    return [arr[i].contents.TargetName for i in range(n.value)]
    finally: a.CredFree(arr)

def _ide_state_db():
    """Return the newest IDE state database."""
    cands = []
    for base in (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
                 r"%APPDATA%\Antigravity IDE"):
        p = os.path.join(os.path.expandvars(base), "User", "globalStorage", "state.vscdb")
        if os.path.isfile(p): cands.append(p)
    return max(cands, key=os.path.getmtime) if cands else None

def ide_read():
    db = _ide_state_db()
    if not db: return {}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        cur, out = con.cursor(), {}
        for k in IDE_KEYS:
            row = cur.execute("select value from ItemTable where key=?", (k,)).fetchone()
            if row is not None: out[k] = row[0]
        return out
    finally: con.close()

def ide_write(values):
    db = _ide_state_db()
    if not db: raise OSError("IDE state.vscdb not found")
    con = sqlite3.connect(db, timeout=2)
    try:
        cur = con.cursor()
        for k in IDE_KEYS:
            if k in values:
                cur.execute("insert into ItemTable(key,value) values(?,?) "
                            "on conflict(key) do update set value=excluded.value", (k, values[k]))
            else:
                cur.execute("delete from ItemTable where key=?", (k,))
        con.commit()
    finally: con.close()

# Preserve SQLite value types in JSON.
def _enc(v): return {"b": base64.b64encode(v).decode()} if isinstance(v, (bytes, bytearray)) else {"s": v}
def _dec(d): return base64.b64decode(d["b"]) if "b" in d else d["s"]

def _snapshot(target_type):
    if target_type == "cli-manager":
        cred = cred_read(CRED_TARGET)
        return {"version": 1, "type": "cli-manager", "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cred": base64.b64encode(cred).decode() if cred else None}
    elif target_type == "ide":
        return {"version": 1, "type": "ide", "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ide": {k: _enc(v) for k, v in ide_read().items()}}
    else:
        raise ValueError(f"unknown target type {target_type}")

def _apply(target_type, bundle):
    if target_type == "cli-manager":
        if bundle.get("cred"):
            cred_write(CRED_TARGET, base64.b64decode(bundle["cred"]), CRED_USER)
    elif target_type == "ide":
        ide = {k: _dec(v) for k, v in (bundle.get("ide") or {}).items()}
        if ide:
            if _ide_state_db():
                ide_write(ide)
            else:
                info("IDE database not found — skipping IDE token restoration")

def _ide_refresh_token(oauth_token_val):
    if not oauth_token_val:
        return None
    try:
        dec = base64.b64decode(oauth_token_val)
        match = re.search(rb'(CoQC[a-zA-Z0-9_-]+)', dec)
        if not match:
            return None
        b64_str = match.group(1)
        raw = base64.urlsafe_b64decode(b64_str + b'===')
        rt_match = re.search(rb'1//[a-zA-Z0-9_-]+', raw)
        return rt_match.group(0).decode("utf-8") if rt_match else None
    except Exception:
        return None

def _refresh_token(target_type, bundle):
    """Extract the refresh token used to identify a profile."""
    if target_type == "cli-manager":
        b64 = bundle.get("cred")
        if not b64: return None
        try:    return json.loads(base64.b64decode(b64)).get("token", {}).get("refresh_token")
        except Exception: return None
    elif target_type == "ide":
        ide_data = bundle.get("ide") or {}
        token_val = ide_data.get("antigravityUnifiedStateSync.oauthToken")
        if not token_val: return None
        try:
            raw_val = _dec(token_val)
            return _ide_refresh_token(raw_val)
        except Exception:
            return None
    return None

# Credential Manager blobs are limited to about 2560 bytes.
_CHUNK = 2000

def _acct_prefix(target_type):
    return f"agy-manager:account:{target_type}:"

def profile_names(target_type):
    prefix = _acct_prefix(target_type)
    return sorted({t[len(prefix):].rsplit("/", 1)[0] for t in cred_enum(prefix)})

def profile_load(target_type, name):
    prefix = _acct_prefix(target_type)
    chunks, i = [], 0
    while True:
        raw = cred_read(f"{prefix}{name}/{i}")
        if raw is None: break
        chunks.append(raw); i += 1
    return json.loads(b"".join(chunks)) if chunks else None

def _profile_delete(target_type, name):
    prefix = _acct_prefix(target_type)
    i = n = 0
    while cred_delete(f"{prefix}{name}/{i}"): n += 1; i += 1
    return n

def profile_save(target_type, name, bundle):
    prefix = _acct_prefix(target_type)
    _profile_delete(target_type, name)
    data = json.dumps(bundle).encode("utf-8")
    parts = [data[j:j+_CHUNK] for j in range(0, len(data), _CHUNK)] or [b""]
    for i, part in enumerate(parts):
        cred_write(f"{prefix}{name}/{i}", part, name)

def current_account(target_type):
    """Match the live refresh token to a saved profile."""
    if target_type == "cli-manager":
        live = cred_read(CRED_TARGET)
        if not live: return None
        try:    rt = json.loads(live).get("token", {}).get("refresh_token")
        except Exception: return None
    elif target_type == "ide":
        db = _ide_state_db()
        if not db: return None
        live = ide_read().get("antigravityUnifiedStateSync.oauthToken")
        if not live: return None
        rt = _ide_refresh_token(live)
    else:
        return None

    if not rt: return None
    for name in profile_names(target_type):
        b = profile_load(target_type, name)
        if b and _refresh_token(target_type, b) == rt: return name
    return None

def _accounts_busy(target_type):
    """Return apps that may cache or lock the active login."""
    busy = []
    if target_type == "cli-manager":
        for t, label in (("manager", "Manager"), ("cli", "CLI")):
            p = resolve(t, {})
            if p and is_locked(p): busy.append(label)
    elif target_type == "ide":
        db = _ide_state_db()
        if db:
            try:
                con = sqlite3.connect(db, timeout=0.3)
                try: con.execute("BEGIN IMMEDIATE"); con.rollback()
                finally: con.close()
            except sqlite3.OperationalError:
                busy.append("IDE")
    return busy

def acct_list(target_type):
    names = profile_names(target_type)
    if not names:
        info(f"no saved accounts yet - use 'accounts {target_type} save <name>'"); return 0
    cur = current_account(target_type)
    for n in names:
        b = profile_load(target_type, n) or {}
        ok(f"{'* ' if n == cur else '  '}{n}   (saved {b.get('saved_at', '?')})")
    if cur is None:
        info("the current live login is not saved as any profile")
    return 0

def acct_current(target_type):
    cur = current_account(target_type)
    (ok if cur else info)(f"active account: {cur}" if cur else "current login is not saved as a profile")
    return 0

def acct_save(target_type, name):
    if "/" in name:
        warn("account name can't contain '/'"); return 1
    snap = _snapshot(target_type)
    if target_type == "cli-manager":
        if not snap["cred"]:
            warn("no active login found to save - log in to Antigravity first"); return 1
    elif target_type == "ide":
        if not _ide_state_db():
            warn("IDE database not found"); return 1
        if not any(snap["ide"].values()):
            warn("no active login found to save - log in to Antigravity IDE first"); return 1
    profile_save(target_type, name, snap)
    ok(f"saved current login as '{name}'"); return 0

def acct_use(target_type, name):
    target = profile_load(target_type, name)
    if target is None:
        warn(f"no saved account '{name}' (see 'accounts {target_type} list')"); return 1
    busy = _accounts_busy(target_type)
    if busy:
        warn(f"close {', '.join(busy)} first - the token is cached in memory while running"); return 1
    cur = current_account(target_type)
    if cur and cur != name:
        try: profile_save(target_type, cur, _snapshot(target_type)); info(f"synced '{cur}' before switching")
        except Exception as e: warn(f"couldn't sync '{cur}': {e}")
    try:
        _apply(target_type, target)
    except sqlite3.OperationalError:
        warn("IDE database is locked - close Antigravity IDE and retry"); return 1
    ok(f"switched to '{name}' - (re)start Antigravity to use it"); return 0

def acct_rm(target_type, name):
    if _profile_delete(target_type, name):
        ok(f"removed account '{name}'"); return 0
    warn(f"no saved account '{name}'"); return 1

def acct_rename(target_type, old_name, new_name):
    if "/" in new_name:
        warn("new name can't contain '/'"); return 1
    target = profile_load(target_type, old_name)
    if target is None:
        warn(f"no saved account '{old_name}'"); return 1
    if profile_load(target_type, new_name) is not None:
        warn(f"account '{new_name}' already exists"); return 1
    profile_save(target_type, new_name, target)
    _profile_delete(target_type, old_name)
    ok(f"renamed account '{old_name}' to '{new_name}'"); return 0

def acct_logout(target_type):
    """Clear the live login locally without revoking its refresh token."""
    busy = _accounts_busy(target_type)
    if busy:
        warn(f"close {', '.join(busy)} first - the token is cached in memory while running"); return 1
    cur = current_account(target_type)
    if cur:
        try: profile_save(target_type, cur, _snapshot(target_type)); info(f"synced '{cur}' first")
        except Exception as e: warn(f"couldn't sync '{cur}': {e}")
    
    if target_type == "cli-manager":
        cred_delete(CRED_TARGET)
        ok("live CLI/Manager login cleared locally (NOT revoked) - launch Antigravity, "
           "sign into the next account, then `accounts cli-manager save <name>`")
    elif target_type == "ide":
        try:
            if _ide_state_db():
                ide_write({})
        except sqlite3.OperationalError:
            warn("IDE database is locked - close Antigravity IDE and retry"); return 1
        ok("live IDE login cleared locally (NOT revoked) - launch Antigravity IDE, "
           "sign into the next account, then `accounts ide save <name>`")
    return 0

def run_accounts(argv):
    if os.name != "nt":
        warn("account management is Windows-only"); return 2
    if not argv:
        warn("usage: accounts <cli-manager|ide> <list|save|use|rename|current|logout|rm> [name1] [name2]"); return 1
    
    target_type = argv[0].lower()
    if target_type not in ("cli-manager", "ide"):
        warn(f"unknown account target '{target_type}' (choose: cli-manager | ide)")
        warn("usage: accounts <cli-manager|ide> <list|save|use|rename|current|logout|rm> [name1] [name2]"); return 1

    sub = (argv[1] if len(argv) > 1 else "list").lower()
    arg = argv[2] if len(argv) > 2 else None
    need = lambda: (warn(f"usage: accounts {target_type} {sub} <name>"), 1)[1]
    try:
        if sub in ("list", "ls"):          return acct_list(target_type)
        if sub in ("current", "who"):      return acct_current(target_type)
        if sub == "save":                  return acct_save(target_type, arg) if arg else need()
        if sub in ("use", "switch"):       return acct_use(target_type, arg)  if arg else need()
        if sub in ("rm", "remove", "del"): return acct_rm(target_type, arg)   if arg else need()
        if sub in ("rename", "mv"):
            arg2 = argv[3] if len(argv) > 3 else None
            need_rename = lambda: (warn(f"usage: accounts {target_type} {sub} <old_name> <new_name>"), 1)[1]
            return acct_rename(target_type, arg, arg2) if (arg and arg2) else need_rename()
        if sub in ("logout", "signout", "clear"): return acct_logout(target_type)
    except Exception as e:
        warn(f"accounts error: {e}"); return 1
    warn(f"unknown accounts subcommand '{sub}' (list | current | save | use | rename | logout | rm)"); return 2

# Driver
SPEC = {
    "cli":     dict(name="Antigravity CLI",      find=cli_default_paths,     status=functools.partial(gate_status, gate=CLI_GATE),
                    patch=functools.partial(gate_patch, gate=CLI_GATE, app="CLI", fname=_bin("agy"))),
    "manager": dict(name="Antigravity Manager",  find=manager_default_bins,  status=functools.partial(gate_status, gate=MANAGER_GATE),
                    patch=functools.partial(gate_patch, gate=MANAGER_GATE, app="Manager", fname=_bin("language_server"))),
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
                    if not restore_file(path, spec["status"]): rc = 1
                else:
                    warn("not patched — skipping restore (backup may be a different build)")
        except Exception as e:
            warn(f"error: {e}"); rc = 1
    return rc

def _status_of(t, path):
    if not path: return "not found"
    try:
        return SPEC[t]["status"](path)[0]
    except Exception:
        return "error"

def state(t, overrides=None):
    path = resolve(t, (overrides or {}).get(t))
    return path, _status_of(t, path)

def scan(overrides):
    """Resolve and scan all targets concurrently."""
    _reg_install_dirs.cache_clear(); _roots.cache_clear()
    _roots()
    def one(t):
        p = resolve(t, overrides.get(t))
        return t, p, _status_of(t, p)
    paths, status = {}, {}
    with ThreadPoolExecutor(max_workers=len(TARGETS)) as ex:
        for t, p, st in ex.map(one, TARGETS):
            paths[t], status[t] = p, st
    return paths, status

# Interactive UI
_STYLE = {"patched": "bold green", "unpatched": "yellow", "unknown": "magenta",
          "not found": "dim", "error": "bold red"}
_ICON  = {"patched": "✓", "unpatched": "●", "unknown": "?", "not found": "·", "error": "!"}

def _render(console, paths, status):
    from rich.table import Table
    from rich.panel import Panel
    cur_cli_manager = None
    cur_ide = None
    if os.name == "nt":
        try:
            cur_cli_manager = current_account("cli-manager")
            cur_ide = current_account("ide")
        except Exception:
            pass

    tbl = Table(box=None, expand=True, pad_edge=False)
    tbl.add_column("App", style="bold cyan", no_wrap=True)
    tbl.add_column("Status", no_wrap=True)
    tbl.add_column("Account", style="bold green", no_wrap=True)
    tbl.add_column("Location", style="dim", overflow="fold")
    
    for t in TARGETS:
        path, st = paths[t], status[t]
        acct = cur_cli_manager if t in ("cli", "manager") else cur_ide
        acct_str = acct if acct else "[white dim]—[/]"
        tbl.add_row(SPEC[t]["name"], f"[{_STYLE[st]}]{_ICON[st]} {st}[/]", acct_str, path or "—")
        
    console.print(Panel(tbl, title="[bold white]agy-manager[/] · Antigravity environment manager",
                        subtitle="[dim]↑↓ move · enter select · space toggle[/]", border_style="cyan"))

def _accounts_submenu(console, qs, target_type):
    import questionary
    from rich.table import Table
    from rich.panel import Panel
    label = "CLI + Manager" if target_type == "cli-manager" else "IDE"
    while True:
        console.clear()
        try:
            names, cur = profile_names(target_type), current_account(target_type)
        except Exception as e:
            console.print(f"[bold red]accounts error:[/] {e}")
            questionary.press_any_key_to_continue("Enter to continue…", style=qs).ask(); return
        tbl = Table(box=None, expand=True, pad_edge=False)
        tbl.add_column("Account", style="bold cyan"); tbl.add_column("", style="bold green", no_wrap=True)
        if names:
            for n in names: tbl.add_row(n, "● active" if n == cur else "")
        else:
            tbl.add_row("[dim]— none saved —[/]", "")
        console.print(Panel(tbl, title=f"[bold white]accounts ({label})[/] · switch login",
                            border_style="cyan"))
        if names and cur is None:
            console.print("[dim]the current login isn't saved as a profile yet[/]")
        act = questionary.select("Accounts:", style=qs, qmark="»", choices=[
            questionary.Choice("Save current login as…", "save"),
            questionary.Choice("Switch to…", "use"),
            questionary.Choice("Rename…", "rename"),
            questionary.Choice("Sign out locally", "logout"),
            questionary.Choice("Remove…", "rm"),
            questionary.Choice("Back", "back"),
        ]).ask()
        if act in (None, "back"): return
        console.rule(f"[bold cyan]{act}[/]")
        if act == "save":
            name = questionary.text("Name for this account:", style=qs).ask()
            if name and name.strip(): acct_save(target_type, name.strip())
        elif act == "logout":
            acct_logout(target_type)
        elif act == "use":
            if not names: console.print("[yellow]Nothing saved yet.[/]")
            else:
                choices = [questionary.Choice(n, n) for n in names] + [questionary.Choice("Back", "back")]
                name = questionary.select("Switch to:", style=qs, choices=choices).ask()
                if name and name != "back": acct_use(target_type, name)
        elif act == "rename":
            if not names: console.print("[yellow]Nothing saved yet.[/]")
            else:
                choices = [questionary.Choice(n, n) for n in names] + [questionary.Choice("Back", "back")]
                old_name = questionary.select("Select account to rename:", style=qs, choices=choices).ask()
                if old_name and old_name != "back":
                    new_name = questionary.text(f"New name for '{old_name}':", style=qs).ask()
                    if new_name and new_name.strip(): acct_rename(target_type, old_name, new_name.strip())
        elif act == "rm":
            if not names: console.print("[yellow]Nothing to remove.[/]")
            else:
                choices = [questionary.Choice(n, n) for n in names] + [questionary.Choice("Back", "back")]
                name = questionary.select("Remove:", style=qs, choices=choices).ask()
                if name and name != "back": acct_rm(target_type, name)
        questionary.press_any_key_to_continue("Enter to continue…", style=qs).ask()

def _accounts_menu(console, qs):
    import questionary
    if os.name != "nt":
        console.print("[yellow]Account management is Windows-only.[/]")
        questionary.press_any_key_to_continue("Enter to continue…", style=qs).ask(); return
    while True:
        console.clear()
        act = questionary.select("Manage accounts for:", style=qs, qmark="»", choices=[
            questionary.Choice("CLI + Manager", "cli-manager"),
            questionary.Choice("IDE", "ide"),
            questionary.Choice("Back", "back"),
        ]).ask()
        if act in (None, "back"): return
        _accounts_submenu(console, qs, act)

def interactive(overrides):
    import questionary
    from rich.console import Console
    console = Console()
    qs = questionary.Style([("qmark", "fg:#00afff bold"), ("pointer", "fg:#00afff bold"),
                            ("highlighted", "fg:#00afff bold"), ("selected", "fg:#00ff87 bold"),
                            ("answer", "fg:#00ff87 bold")])
    paths, status = scan(overrides)
    while True:
        console.clear()
        _render(console, paths, status)
        action = questionary.select("What do you want to do?", style=qs, qmark="»", choices=[
            questionary.Choice("Patch app(s)", "patch"),
            questionary.Choice("Restore app(s) from backup", "restore"),
            questionary.Choice("Manage accounts", "accounts"),
            questionary.Choice("Refresh status", "refresh"),
            questionary.Choice("Quit", "quit"),
        ]).ask()
        if action in (None, "quit"):
            console.print("[dim]bye 👋[/]"); return 0
        if action == "refresh":
            paths, status = scan(overrides)
            continue
        if action == "accounts":
            _accounts_menu(console, qs); continue
        opts = []
        for t in TARGETS:
            path, st = paths[t], status[t]
            if not path:
                continue
            if action == "patch" and st == "patched": continue
            if action == "restore" and st != "patched": continue
            opts.append(questionary.Choice(f"{SPEC[t]['name']}  · {st}", value=t))
        if not opts:
            console.print(f"[yellow]Nothing to {action}.[/]")
            questionary.press_any_key_to_continue("Enter to continue…", style=qs).ask(); continue
        sel = questionary.checkbox(f"Select app(s) to {action}:", choices=opts, style=qs).ask()
        if not sel:
            continue
        console.rule(f"[bold cyan]{action}[/]")
        run(action, sel, overrides)
        for t in sel:
            status[t] = _status_of(t, paths[t])
        console.rule(style="dim")
        questionary.press_any_key_to_continue("Enter to return to the menu…", style=qs).ask()

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Manage the Antigravity environment (patch location gates and manage profiles). "
                    "Run with no arguments for the interactive menu.")
    ap.add_argument("action", choices=("menu", "status", "patch", "restore", "accounts"), nargs="?",
                    help="menu (default) | status | patch | restore | "
                         "accounts <cli-manager|ide> <list|save|use|rename|current|logout|rm> [name1] [name2]")
    ap.add_argument("targets", nargs="*", default=[], metavar="{cli,manager,ide}",
                    help="which apps to act on (default: all)")
    for t in TARGETS: ap.add_argument(f"--path-{t}", help=f"explicit path for {t}")
    args = ap.parse_args(argv)

    if args.action == "accounts":
        return run_accounts(args.targets)

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
        print("agy-manager - status")
        return run("status", list(TARGETS), overrides)

    targets = args.targets if args.targets else list(TARGETS)
    print(f"agy-manager - {args.action}")
    return run(args.action, targets, overrides)

if __name__ == "__main__":
    raise SystemExit(main())
