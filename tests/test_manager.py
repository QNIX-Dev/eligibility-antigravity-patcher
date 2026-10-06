import base64
import contextlib
import errno
import io
import json
import os
import plistlib
import sqlite3
import struct
import tempfile
import unittest
from unittest import mock

import manager


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _minimal_pe(code=b"", data=b"", machine=0x8664):
    # One executable and one data section.
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, machine)
    struct.pack_into("<H", image, 0x86, 2)
    struct.pack_into("<H", image, 0x94, 0)
    section_table = 0x98
    image[section_table:section_table + 8] = b".text\0\0\0"
    struct.pack_into("<II", image, section_table + 16, 0x40, 0x200)
    struct.pack_into("<I", image, section_table + 36, 0x60000020)
    second = section_table + 40
    image[second:second + 8] = b".data\0\0\0"
    struct.pack_into("<II", image, second + 16, 0x40, 0x280)
    struct.pack_into("<I", image, second + 36, 0xC0000040)
    image[0x200:0x200 + len(code)] = code
    image[0x280:0x280 + len(data)] = data
    return bytes(image)


def _minimal_elf(machine=0x3E):
    # One executable and one read-only segment.
    image = bytearray(0x200)
    image[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", image, 18, machine)
    struct.pack_into("<Q", image, 32, 64)
    struct.pack_into("<HH", image, 54, 56, 2)
    struct.pack_into("<II", image, 64, 1, 5)
    struct.pack_into("<Q", image, 72, 0x100)
    struct.pack_into("<Q", image, 96, 0x20)
    second = 64 + 56
    struct.pack_into("<II", image, second, 1, 4)
    struct.pack_into("<Q", image, second + 8, 0x120)
    struct.pack_into("<Q", image, second + 32, 0x20)
    return bytes(image)


def _minimal_macho(cputype=0x01000007):
    # One __TEXT,__text section.
    image = bytearray(0x300)
    image[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", image, 4, cputype)
    struct.pack_into("<I", image, 16, 1)
    struct.pack_into("<I", image, 20, 152)
    command = 32
    struct.pack_into("<II", image, command, 0x19, 152)
    struct.pack_into("<I", image, command + 64, 1)
    section = command + 72
    image[section:section + 16] = b"__text" + b"\0" * 10
    image[section + 16:section + 32] = b"__TEXT" + b"\0" * 10
    struct.pack_into("<Q", image, section + 40, 0x20)
    struct.pack_into("<I", image, section + 48, 0x200)
    struct.pack_into("<I", image, section + 64, 0x80000400)
    return bytes(image)

def _minimal_fat_macho(cputypes=(0x01000007,)):
    image = bytearray(0x100 + len(cputypes) * 0x400)
    image[:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", image, 4, len(cputypes))
    for i, cputype in enumerate(cputypes):
        thin = _minimal_macho(cputype)
        offset = 0x100 + i * 0x400
        struct.pack_into(">IIIII", image, 8 + i * 20, cputype, 3, offset, len(thin), 8)
        image[offset:offset + len(thin)] = thin
    return bytes(image)


def _mac_app(tmp, electron=False):
    tmp = os.path.realpath(tmp)
    app = os.path.join(tmp, "Antigravity.app")
    contents = os.path.join(app, "Contents")
    main = os.path.join(contents, "MacOS", "Antigravity")
    signature = os.path.join(contents, "_CodeSignature", "CodeResources")
    language_server = os.path.join(contents, "Resources", "bin", "language_server")
    main_js = os.path.join(contents, "Resources", "app", "out", "main.js")
    for path in (main, signature, language_server, main_js):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.path.join(contents, "Info.plist"), "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Antigravity"}, f)
    _write(main, b"vendor-main-signature")
    _write(signature, b"vendor-resource-envelope")
    _write(language_server, _minimal_macho())
    _write(main_js, b"original-js")
    if electron:
        framework = os.path.join(contents, "Frameworks", "Electron Framework.framework", "Electron Framework")
        os.makedirs(os.path.dirname(framework))
        _write(framework, b"vendor-framework-signature")
    return app, main, signature, language_server, main_js


class GateStateTests(unittest.TestCase):
    def setUp(self):
        self.gate = manager.Gate(b"ORIG", b"DONE", b"DONE")

    def test_unique_original_and_patched_states(self):
        self.assertEqual(self.gate.find(b"xxORIGyy"), ("unpatched", 2))
        self.assertEqual(self.gate.find(b"xxDONEyy"), ("patched", 2))

    def test_duplicate_and_mixed_signatures_are_ambiguous(self):
        for data in (b"ORIG--ORIG", b"DONE--DONE", b"ORIG--DONE"):
            with self.subTest(data=data), self.assertRaises(manager.SignatureAmbiguous):
                self.gate.find(data)

    def test_ranges_exclude_data_matches(self):
        self.assertEqual(self.gate.find(b"ORIG--ORIG", ((0, 4),)), ("unpatched", 0))

    def test_multigate_refuses_multiple_architectures(self):
        other = manager.Gate(b"ARCH", b"PCHD", b"PCHD")
        multi = manager.MultiGate(self.gate, other)
        with self.assertRaises(manager.SignatureAmbiguous):
            multi.resolve(b"ORIG--ARCH")

    def test_multigate_scans_only_matching_architecture(self):
        x64 = manager.Gate(b"X64", b"X64P", b"X64P", arch="x64")
        arm64 = manager.Gate(b"ARM", b"ARMP", b"ARMP", arch="arm64")
        multi = manager.MultiGate(x64, arm64)
        self.assertEqual(multi.resolve(b"X64--ARM", arch="x64"), ("unpatched", 0, x64))
        self.assertEqual(multi.resolve(b"X64--ARM", arch="arm64"), ("unpatched", 5, arm64))
        with self.assertRaises(manager.SignatureAmbiguous):
            multi.resolve(b"X64--ARM")

    def test_current_cli_x64_signature_and_patch(self):
        # CLI 1.2.16 Windows x64, file offset 0x29fa500, SHA256
        # 871e1eeb205dd3269b762e81808b7a86fe7cf73b59da51b14e3d8ac005581bfe.
        source = bytes.fromhex(
            "4885c00f8498020000807808000f858e020000"
            "e8284afdff48898424d800000048899c24e000000048898c24e8000000")
        state, offset, gate = manager.CLI_GATE.resolve(source, arch="x64")
        self.assertEqual((state, offset, gate), ("unpatched", 9, manager.CLI_GATE_X64))
        patched = source[:offset] + gate.fix + source[offset + len(gate.fix):]
        self.assertEqual(manager.CLI_GATE.resolve(patched, arch="x64"),
                         ("patched", 9, gate))

    def test_current_cli_arm64_signature_and_patch(self):
        # CLI 1.2.16 ARM64: identical gate bytes in macOS and Linux builds.
        # macOS Mach-O: ldrb at 0x223bca8, SHA256
        # 7dca095cfc1df2c057a385ed88a76c7ba98dc103258a80be87a8f42e484cb3aa.
        # Linux ELF: ldrb at 0x7d05738, SHA256
        # d0c06173f4ab2d6da7c17ba8d52a688234f30a79a7f65e25ace15863a295695f.
        source = bytes.fromhex(
            "a11800b5200f00b402204039e20e0037d472ff97"
            "e0070ea9e20f0fa9e41710a9e61f11a9")
        state, offset, gate = manager.CLI_GATE.resolve(source, arch="arm64")
        self.assertEqual((state, offset, gate), ("unpatched", 8, manager.CLI_GATE_ARM64))
        patched = source[:offset] + gate.fix + source[offset + len(gate.fix):]
        self.assertEqual(manager.CLI_GATE.resolve(patched, arch="arm64"),
                         ("patched", 8, gate))

    def test_cli_arm64_signature_requires_outer_registers(self):
        wrong_outer_register = bytes.fromhex(
            "a21800b5200f00b402204039e20e0037d472ff97"
            "e0070ea9e20f0fa9e41710a9e61f11a9")
        with self.assertRaises(manager.SignatureNotFound):
            manager.CLI_GATE.resolve(wrong_outer_register, arch="arm64")

    def test_current_manager_x64_signature_and_patch(self):
        # Installed Windows PE x64 backup, file offset 0x29890ca, SHA256
        # d569b7a0fb5c2e3eb6dc867be17e6cde1ad1fac94c7dcda2909d6612c7c31532.
        source = bytes.fromhex("80780800743b488b54247048895060")
        state, offset, gate = manager.MANAGER_GATE.resolve(source, arch="x64")
        self.assertEqual((state, offset, gate), ("unpatched", 0, manager.MANAGER_GATE_X64))
        patched = gate.fix + source[len(gate.fix):]
        self.assertEqual(manager.MANAGER_GATE.resolve(patched, arch="x64"),
                         ("patched", 0, gate))

    def test_current_manager_arm64_signature_and_patch(self):
        # Manager 2.19.1 Linux ELF ARM64, file offset 0x6bd13e0, SHA256
        # 6f738eba385f68d66c83dfd50546346a30688422d364fa398d2f9155586853da.
        source = bytes.fromhex("03204039a3010036e31348a9031006a9")
        state, offset, gate = manager.MANAGER_GATE.resolve(source, arch="arm64")
        self.assertEqual((state, offset, gate), ("unpatched", 0, manager.MANAGER_GATE_ARM64))
        patched = gate.fix + source[len(gate.fix):]
        self.assertEqual(manager.MANAGER_GATE.resolve(patched, arch="arm64"),
                         ("patched", 0, gate))

    def test_manager_arm64_signature_requires_tbz_w3(self):
        wrong_register = bytes.fromhex("03204039a4010036e31348a9031006a9")
        with self.assertRaises(manager.SignatureNotFound):
            manager.MANAGER_GATE.resolve(wrong_register, arch="arm64")


class ExecutableRangeTests(unittest.TestCase):
    def _info(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixture")
            _write(path, payload)
            return manager.executable_info(path)

    def _ranges(self, payload):
        return self._info(payload)[0]

    def test_executable_architectures(self):
        fixtures = ((_minimal_pe(), "x64"), (_minimal_pe(machine=0xAA64), "arm64"),
                    (_minimal_elf(), "x64"), (_minimal_elf(machine=0xB7), "arm64"),
                    (_minimal_macho(), "x64"),
                    (_minimal_macho(cputype=0x0100000C), "arm64"),
                    (_minimal_fat_macho(), "x64"),
                    (_minimal_fat_macho((0x01000007, 0x0100000C)), None))
        for payload, expected in fixtures:
            with self.subTest(expected=expected, magic=payload[:4]):
                self.assertEqual(self._info(payload)[1], expected)

    def test_executable_ranges_by_format(self):
        for payload, expected in ((_minimal_pe(), ((0x200, 0x240),)),
                                  (_minimal_elf(), ((0x100, 0x120),)),
                                  (_minimal_macho(), ((0x200, 0x220),)),
                                  (_minimal_fat_macho(), ((0x300, 0x320),))):
            with self.subTest(magic=payload[:4]):
                self.assertEqual(self._ranges(payload), expected)

    def test_gate_status_ignores_non_executable_match(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"DONE")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixture.exe")
            _write(path, _minimal_pe(code=b"safe", data=b"ORIG"))
            self.assertEqual(manager.gate_status(path, gate)[0], "unknown")
            _write(path, _minimal_pe(code=b"ORIG", data=b"ORIG"))
            self.assertEqual(manager.gate_status(path, gate)[0], "unpatched")

    def test_gate_status_routes_detected_architecture(self):
        x64 = manager.Gate(b"X64", b"X64P", b"X64P", arch="x64")
        arm64 = manager.Gate(b"ARM", b"ARMP", b"ARMP", arch="arm64")
        gate = manager.MultiGate(x64, arm64)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixture.exe")
            _write(path, _minimal_pe(code=b"X64--ARM", machine=0x8664))
            self.assertEqual(manager.gate_status(path, gate)[0], "unpatched")
            _write(path, _minimal_pe(code=b"X64--ARM", machine=0xAA64))
            self.assertEqual(manager.gate_status(path, gate)[0], "unpatched")


class ExtensionTests(unittest.TestCase):
    @staticmethod
    def hub_code():
        # agy 1.3.0 Windows x64, PersonalAuthValidator.Validate at 0x289100a.
        # Original SHA256: c1b0001989c4051a41f5104484de182db5014fa155053c8088baacf1663063bf.
        return bytes.fromhex("80780800743b488b54247048895060")

    @classmethod
    def binary(cls, shared=False):
        code = cls.hub_code()
        if shared:
            # Ordinary CLI gate from the same real agy 1.3.0 executable.
            code = bytes.fromhex(
                "4885c00f8498020000807808000f858e020000e82845fdff"
                "48898424d800000048899c24e000000048898c24e8000000") + b"\x90" * 7 + code
        image = bytearray(_minimal_pe(code=code))
        struct.pack_into("<I", image, 0x98 + 16, 0x80)
        return image

    def test_discovery_uses_extension_install_directory_on_each_platform(self):
        with tempfile.TemporaryDirectory() as home:
            directory = os.path.join(home, ".gemini", "bin")
            os.makedirs(directory)
            for platform in ("nt", "posix"):
                with self.subTest(platform=platform), mock.patch.object(manager.os, "name", platform):
                    path = os.path.join(directory, manager._bin("agy"))
                    _write(path, b"fixture")
                    with (mock.patch.object(manager.os.path, "expanduser", return_value=home),
                          mock.patch.object(manager.shutil, "which") as which):
                        self.assertEqual(manager.resolve("extension", None), path)
                    which.assert_not_called()

    def test_extension_refuses_unverified_arm64_before_write(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "agy.exe")
            original = _minimal_pe(code=self.hub_code(), machine=0xAA64)
            _write(path, original)
            self.assertEqual(manager.main(["patch", "extension", "--path-extension", path]), 1)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)
            self.assertFalse(os.path.exists(path + manager.BAK))

    def test_shared_cli_extension_backup_stays_pristine_in_both_orders(self):
        for order in (("cli", "extension"), ("extension", "cli")):
            with (self.subTest(order=order), tempfile.TemporaryDirectory() as tmp,
                  contextlib.redirect_stdout(io.StringIO())):
                path = os.path.join(tmp, "agy.exe")
                original = self.binary(shared=True)
                _write(path, original)
                args = ["--path-cli", path, "--path-extension", path]
                for target in order:
                    self.assertEqual(manager.SPEC[target]["status"](path)[0], "unpatched")
                self.assertEqual(manager.main(["patch", *order, *args]), 0)
                for target in order:
                    self.assertEqual(manager.SPEC[target]["status"](path)[0], "patched")
                self.assertEqual(manager.gate_status(path, manager.MANAGER_GATE)[0], "patched")
                self.assertEqual(manager.main(["status", "extension", *args]), 0)
                self.assertEqual(manager.main(["patch", "extension", *args]), 0)
                with open(path + manager.BAK, "rb") as f:
                    self.assertEqual(f.read(), original)
                self.assertEqual(manager.main(["restore", order[0], *args]), 0)
                for target in order:
                    self.assertEqual(manager.SPEC[target]["status"](path)[0], "unpatched")
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), original)

    def test_failed_second_gate_restores_first_gate_and_preserves_clean_backup(self):
        for first, second, gate in (("cli", "extension", manager.MANAGER_GATE_X64),
                                    ("extension", "cli", manager.CLI_GATE_X64)):
            with (self.subTest(first=first), tempfile.TemporaryDirectory() as tmp,
                  contextlib.redirect_stdout(io.StringIO())):
                path = os.path.join(tmp, "agy.exe")
                original = self.binary(shared=True)
                _write(path, original)
                overrides = {first: path, second: path}
                self.assertEqual(manager.run("patch", [first], overrides), 0)
                with open(path, "rb") as f:
                    before = f.read()
                with mock.patch.object(gate, "fix", b"\x90" * len(gate.fix)):
                    self.assertEqual(manager.run("patch", [second], overrides), 1)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), before)
                with open(path + manager.BAK, "rb") as f:
                    self.assertEqual(f.read(), original)

    def test_shared_binary_rejects_missing_or_mismatched_backup(self):
        for backup_kind in ("missing", "mismatched", "already_patched"):
            with (self.subTest(backup=backup_kind), tempfile.TemporaryDirectory() as tmp,
                  contextlib.redirect_stdout(io.StringIO())):
                path = os.path.join(tmp, "agy.exe")
                original = self.binary(shared=True)
                _write(path, original)
                overrides = {"cli": path, "extension": path}
                self.assertEqual(manager.run("patch", ["cli"], overrides), 0)
                if backup_kind == "missing":
                    os.unlink(path + manager.BAK)
                elif backup_kind == "mismatched":
                    with open(path, "r+b") as f:
                        f.seek(-1, os.SEEK_END); f.write(b"X")
                with open(path, "rb") as f:
                    before = f.read()
                if backup_kind == "already_patched":
                    _write(path + manager.BAK, before)
                self.assertEqual(manager.run("patch", ["extension"], overrides), 1)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), before)
                if backup_kind == "missing":
                    self.assertFalse(os.path.exists(path + manager.BAK))
                else:
                    with open(path + manager.BAK, "rb") as f:
                        self.assertEqual(f.read(), before if backup_kind == "already_patched" else original)

    def test_changed_target_after_backup_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "agy.exe")
            original = self.binary()
            _write(path, original)
            real_backup = manager.make_backup
            def change_after_backup(*args, **kwargs):
                bak = real_backup(*args, **kwargs)
                with open(path, "r+b") as f:
                    f.seek(-1, os.SEEK_END); f.write(b"X")
                return bak
            with mock.patch.object(manager, "make_backup", side_effect=change_after_backup):
                self.assertEqual(manager.run("patch", ["extension"], {"extension": path}), 1)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original[:-1] + b"X")
            with open(path + manager.BAK, "rb") as f:
                self.assertEqual(f.read(), original)

    def test_updated_unpatched_binary_refreshes_stale_backup(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "agy.exe")
            original = self.binary(shared=True)
            updated = original[:-1] + b"X"
            _write(path + manager.BAK, original)
            _write(path, updated)
            # Equal sizes and timestamps must not reuse a cached comparison
            # after refreshing the backup's contents.
            for filename in (path, path + manager.BAK):
                os.utime(filename, (1_000_000_000, 1_000_000_000))
            overrides = {"extension": path}
            self.assertEqual(manager.run("patch", ["extension"], overrides), 0)
            with open(path + manager.BAK, "rb") as f:
                self.assertEqual(f.read(), updated)
            self.assertEqual(manager.run("restore", ["extension"], overrides), 0)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), updated)

class AccountTests(unittest.TestCase):
    @staticmethod
    def _cli_bundle(refresh_token, saved_at="now"):
        live = json.dumps({"token": {"refresh_token": refresh_token}}).encode()
        return {"cred": base64.b64encode(live).decode(), "saved_at": saved_at}

    def test_account_list_loads_each_profile_once(self):
        bundles = {"first": self._cli_bundle("one"), "second": self._cli_bundle("two")}
        live = json.dumps({"token": {"refresh_token": "one"}}).encode()
        with (mock.patch.object(manager, "profile_names", return_value=list(bundles)),
              mock.patch.object(manager, "profile_load", side_effect=lambda _, n: bundles[n]) as load,
              mock.patch.object(manager, "cred_read", return_value=live),
              contextlib.redirect_stdout(io.StringIO())):
            self.assertEqual(manager.acct_list("cli-manager"), 0)
        self.assertEqual(load.call_count, len(bundles))

    def test_ide_read_fetches_requested_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "state.vscdb")
            con = sqlite3.connect(db)
            try:
                con.execute("create table ItemTable(key text primary key, value)")
                con.execute("insert into ItemTable values(?,?)", (manager.IDE_KEYS[0], "token"))
                con.execute("insert into ItemTable values(?,?)", ("unrelated", "ignored"))
                con.commit()
            finally:
                con.close()
            self.assertEqual(manager.ide_read(db), {manager.IDE_KEYS[0]: "token"})

    @staticmethod
    def _ide_oauth_token(*payloads):
        encoded = [base64.urlsafe_b64encode(payload).rstrip(b"=") for payload in payloads]
        return base64.b64encode(b"\x00" + b"\x00".join(encoded) + b"\x00").decode()

    def test_ide_refresh_token_accepts_rotated_wrapper_prefix(self):
        refresh_token = b"1//fixture-refresh-token_123"
        oauth_token = self._ide_oauth_token(b"new-wrapper-format:" + refresh_token + b"\xff")
        self.assertNotIn(b"CoQC", base64.b64decode(oauth_token))
        self.assertEqual(manager._ide_refresh_token(oauth_token), refresh_token.decode())

    def test_ide_refresh_token_rejects_ambiguous_wrapper(self):
        oauth_token = self._ide_oauth_token(
            b"first-wrapper:1//fixture-refresh-token_one\xff",
            b"second-wrapper:1//fixture-refresh-token_two\xff")
        self.assertIsNone(manager._ide_refresh_token(oauth_token))


class TransactionTests(unittest.TestCase):
    def test_write_access_errors_are_reported_without_modifying_target(self):
        sharing_error = PermissionError(errno.EACCES, "sharing violation")
        sharing_error.winerror = 32
        cases = (
            (PermissionError(errno.EACCES, "Permission denied"), "permission denied", False),
            (OSError(errno.ETXTBSY, "Text file busy"), "is in use", True),
            (OSError(errno.EROFS, "Read-only file system"), "cannot open", False),
            (sharing_error, "is in use", True),
        )
        gate = manager.Gate(rb"ORIG", rb"DONE", b"DONE")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "language_server")
            original = _minimal_pe(code=b"ORIG")
            _write(path, original)
            for error, message, in_use in cases:
                with self.subTest(error=str(error)), contextlib.redirect_stdout(io.StringIO()) as output:
                    with (mock.patch("builtins.open", side_effect=error),
                          mock.patch.object(manager, "make_backup") as backup):
                        self.assertFalse(manager.gate_patch(path, gate, "Manager", "language_server"))
                    backup.assert_not_called()
                    self.assertIn(message, output.getvalue())
                    self.assertIn(str(error), output.getvalue())
                    self.assertEqual("close Manager" in output.getvalue(), in_use)
                    with open(path, "rb") as f:
                        self.assertEqual(f.read(), original)

    def test_macos_scan_patch_and_restore_never_map_file_pages(self):
        gate = manager.Gate(rb"ORIG", rb"DONE", b"DONE", arch="arm64")
        status = lambda path: manager.gate_status(path, gate)
        with (tempfile.TemporaryDirectory() as tmp,
              contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch.object(manager.mmap, "mmap",
                                side_effect=AssertionError("unsafe file mapping")) as mapping):
            path = os.path.join(tmp, "fixture")
            original = bytearray(_minimal_macho(0x0100000C))
            original[0x200:0x204] = b"ORIG"
            _write(path, original)
            self.assertEqual(status(path)[0], "unpatched")
            self.assertTrue(manager.gate_patch(path, gate, "Fixture", "fixture"))
            self.assertEqual(status(path)[0], "patched")
            self.assertTrue(manager.restore_file(path, status))
            self.assertEqual(status(path)[0], "unpatched")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)
            mapping.assert_not_called()

    def test_macos_failed_verification_still_rolls_back_without_mmap(self):
        with (mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch.object(manager.mmap, "mmap",
                                side_effect=AssertionError("unsafe file mapping")) as mapping):
            self.test_failed_binary_verification_rolls_back()
            mapping.assert_not_called()

    def test_binary_patch_is_verified_idempotent_and_restorable(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"DONE")
        status = lambda path: manager.gate_status(path, gate)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "fixture.exe")
            original = _minimal_pe(code=b"ORIG")
            _write(path, original)
            self.assertTrue(manager.gate_patch(path, gate, "Fixture", "fixture.exe"))
            self.assertEqual(status(path)[0], "patched")
            self.assertTrue(manager.gate_patch(path, gate, "Fixture", "fixture.exe"))
            self.assertTrue(manager.restore_file(path, status))
            self.assertEqual(status(path)[0], "unpatched")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)

    def test_failed_binary_verification_rolls_back(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"FAIL")
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "fixture.exe")
            original = _minimal_pe(code=b"ORIG")
            _write(path, original)
            self.assertFalse(manager.gate_patch(path, gate, "Fixture", "fixture.exe"))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)

    def test_restore_refuses_unrecognized_backup(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"DONE")
        status = lambda path: manager.gate_status(path, gate)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "fixture.exe")
            live = _minimal_pe(code=b"DONE")
            _write(path, live)
            _write(path + manager.BAK, _minimal_pe(code=b"OTHER"))
            self.assertFalse(manager.restore_file(path, status))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), live)

    def test_ide_patch_requires_one_gate_and_restores(self):
        source = b"before;resetIsTierGCPTos(),this.account.isGoogleInternal;after"
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "main.js")
            _write(path, source)
            with mock.patch.object(manager, "_ide_cache_dirs", return_value=[]):
                self.assertTrue(manager.ide_patch(path))
                self.assertEqual(manager.ide_status(path)[0], "patched")
                self.assertTrue(manager.ide_patch(path))
                self.assertTrue(manager.restore_file(path, manager.ide_status))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), source)

    def test_ide_refuses_duplicate_and_mixed_gates(self):
        original = b"resetIsTierGCPTos(),this.a.isGoogleInternal"
        patched = manager.IDE_DONE
        with self.assertRaises(manager.SignatureAmbiguous):
            manager._ide_gate_state(original + b";" + original)
        with self.assertRaises(manager.SignatureAmbiguous):
            manager._ide_gate_state(original + b";" + patched)


class MacCodeSigningTests(unittest.TestCase):
    def test_electron_preflight_failures_leave_app_untouched(self):
        for failure in ("conflict", "entitlements", "entitlement_type", "flags", "team", "read"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                app, main, signature, _, main_js = _mac_app(tmp, electron=True)
                source = b"resetIsTierGCPTos(),this.account.isGoogleInternal"
                _write(main_js, source)
                originals = {path: manager._mac_entry_digest(path) for path in (main, signature, main_js)}

                def command(args, check=True):
                    if failure == "read":
                        raise OSError("fixture codesign read failure")
                    if "--entitlements" in args:
                        values = {manager.MAC_DISABLE_LIBRARY_VALIDATION: "true"} if failure == "entitlement_type" else {}
                        xml = "<plist>" if failure == "entitlements" else plistlib.dumps(values).decode()
                        return manager.subprocess.CompletedProcess(args, 0, xml, "")
                    details = "" if failure == "team" else "TeamIdentifier=GOOGLE\n"
                    if failure != "flags":
                        details += "CodeDirectory flags=0x10000(runtime)\n"
                    return manager.subprocess.CompletedProcess(args, 0, "", details)

                with (mock.patch.object(manager, "_mac_command", side_effect=command),
                      mock.patch.object(manager, "_mac_prepare_signature_backup") as backup,
                      mock.patch.object(manager, "_mac_sign_transaction") as sign,
                      contextlib.redirect_stdout(io.StringIO()) as output):
                    self.assertEqual(manager._mac_run_patch(["ide"], {"ide": main_js}), 1)
                backup.assert_not_called()
                sign.assert_not_called()
                self.assertFalse(os.path.exists(main_js + manager.BAK))
                for path, digest in originals.items():
                    self.assertEqual(manager._mac_entry_digest(path), digest)
                if failure == "conflict":
                    self.assertIn("--macos-disable-library-validation", output.getvalue())

    def test_electron_without_library_validation_conflict_needs_no_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _, _, _, _ = _mac_app(tmp, electron=True)
            for flags, entitlements in (("0x0(none)", {}),
                                        ("0x10000(runtime)", {manager.MAC_DISABLE_LIBRARY_VALIDATION: True})):
                with self.subTest(flags=flags):
                    def command(args, check=True):
                        xml = plistlib.dumps(entitlements).decode() if "--entitlements" in args else ""
                        return manager.subprocess.CompletedProcess(args, 0, xml, "CodeDirectory flags=" + flags)
                    with mock.patch.object(manager, "_mac_command", side_effect=command):
                        self.assertIsNone(manager._mac_library_validation_entitlements(app))

    def test_electron_opt_in_signing_preserves_entitlements_and_rolls_back_failures(self):
        for failure in (None, "sign", "verify", "entitlements", "metadata"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                app, main, signature, _, main_js = _mac_app(tmp, electron=True)
                framework = os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework", "Electron Framework")
                source = b"resetIsTierGCPTos(),this.account.isGoogleInternal"
                _write(main_js, source)
                originals = {path: manager._mac_entry_digest(path) for path in (main, signature, main_js, framework)}
                original_entitlements = {"com.apple.security.cs.allow-jit": True,
                                         "com.apple.security.cs.allow-unsigned-executable-memory": False}
                expected = {**original_entitlements, manager.MAC_DISABLE_LIBRARY_VALIDATION: True}
                signed_paths = []

                def command(args, check=True):
                    with open(main, "rb") as f:
                        signed = f.read() != b"vendor-main-signature"
                    if failure == "metadata" and "-d" in args and "--verbose=2" in args:
                        if manager.ide_status(main_js)[0] == "patched":
                            return manager.subprocess.CompletedProcess(args, 1, "", "fixture metadata read failure")
                    if "--sign" in args:
                        self.assertEqual(args[-1], app)
                        self.assertNotIn("--deep", args)
                        self.assertIn("--preserve-metadata=identifier,flags,runtime", args)
                        with open(args[args.index("--entitlements") + 1], "rb") as f:
                            self.assertEqual(plistlib.load(f), expected)
                        signed_paths.append(args[-1])
                        _write(main, b"ad-hoc-main-signature")
                        _write(signature, b"ad-hoc-resource-envelope")
                        if failure == "sign":
                            raise OSError("fixture signing failure")
                    elif "--verify" in args and signed and failure == "verify":
                        raise OSError("fixture verification failure")
                    elif "--entitlements" in args:
                        entitlements = expected if signed and failure != "entitlements" else original_entitlements
                        return manager.subprocess.CompletedProcess(args, 0, plistlib.dumps(entitlements).decode(), "")
                    details = "CodeDirectory flags=0x10000(runtime)\n"
                    details += "Signature=adhoc\nTeamIdentifier=not set\n" if signed else "TeamIdentifier=GOOGLE\n"
                    return manager.subprocess.CompletedProcess(args, 0, "", details)

                with (mock.patch.object(manager.sys, "platform", "darwin"),
                      mock.patch.object(manager, "_mac_command", side_effect=command),
                      mock.patch.object(manager, "_mac_remove_quarantine"),
                      contextlib.redirect_stdout(io.StringIO())):
                    result = manager.main(["--macos-disable-library-validation", "--path-ide", main_js, "patch", "ide"])
                    self.assertEqual(result, 0 if failure is None else 1)
                    if failure is None:
                        self.assertEqual(manager.ide_status(main_js)[0], "patched")
                        self.assertEqual(manager.main(["--path-ide", main_js, "restore", "ide"]), 0)
                self.assertEqual(signed_paths, [] if failure == "metadata" else [app])
                for path, digest in originals.items():
                    self.assertEqual(manager._mac_entry_digest(path), digest)

    def test_macos_signature_snapshot_restores_outer_bundle_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, main, signature, _, _ = _mac_app(tmp)
            snapshot = os.path.join(tmp, "snapshot")
            os.makedirs(snapshot)
            manager._mac_write_signature_snapshot(app, snapshot)

            _write(main, b"ad-hoc-main-signature")
            _write(signature, b"ad-hoc-resource-envelope")
            manager._mac_restore_signature_snapshot(snapshot, app)

            with open(main, "rb") as f:
                self.assertEqual(f.read(), b"vendor-main-signature")
            with open(signature, "rb") as f:
                self.assertEqual(f.read(), b"vendor-resource-envelope")

    def test_macos_signs_each_binary_then_bundle_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            app, _, _, language_server, main_js = _mac_app(tmp)
            agy = os.path.join(tmp, "agy")
            extension = os.path.join(tmp, "hub-agy")
            _write(agy, _minimal_macho())
            _write(extension, _minimal_macho())
            calls = []

            def record(path, bundle=False):
                calls.append((path, bundle))

            with (mock.patch.object(manager, "_mac_codesign", side_effect=record),
                  contextlib.redirect_stdout(io.StringIO())):
                manager._mac_sign_transaction(
                    {"cli": agy, "manager": language_server, "ide": main_js, "extension": extension})

            self.assertEqual(calls, [(agy, False), (language_server, False), (extension, False), (app, True)])

    def test_macos_signing_failure_restores_every_modified_signature_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, main, signature, language_server, _ = _mac_app(tmp)
            originals = {}
            for path in (main, signature, language_server):
                with open(path, "rb") as f:
                    originals[path] = f.read()

            def fail_on_bundle(path, bundle=False):
                if bundle:
                    _write(main, b"partially-signed-main")
                    _write(signature, b"partially-signed-envelope")
                    raise OSError("fixture signing failure")
                _write(path, b"partially-signed-binary")

            with (mock.patch.object(manager, "_mac_codesign", side_effect=fail_on_bundle),
                  self.assertRaises(OSError)):
                manager._mac_sign_transaction({"manager": language_server})

            for path, original in originals.items():
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), original)

    def test_macos_restore_returns_persistent_vendor_bundle_signature(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            app, main, signature, _, _ = _mac_app(tmp)
            backup = app + manager.MAC_SIGNATURE_BAK
            os.makedirs(backup)
            manager._mac_write_signature_snapshot(app, backup)
            _write(main, b"ad-hoc-main-signature")
            _write(signature, b"ad-hoc-resource-envelope")

            with mock.patch.object(manager, "_mac_codesign_verify") as verify:
                manager._mac_restore_bundle_signature(app)

            verify.assert_called_once_with(app, bundle=True)
            with open(main, "rb") as f:
                self.assertEqual(f.read(), b"vendor-main-signature")
            with open(signature, "rb") as f:
                self.assertEqual(f.read(), b"vendor-resource-envelope")

    def test_macos_patch_signing_failure_rolls_back_new_gate(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"DONE")
        spec = {
            "name": "Fixture CLI",
            "find": lambda: [],
            "status": lambda path: manager.gate_status(path, gate),
            "patch": lambda path: manager.gate_patch(path, gate, "Fixture", "agy"),
        }
        for target in ("cli", "extension"):
            with (self.subTest(target=target), tempfile.TemporaryDirectory() as tmp,
                  contextlib.redirect_stdout(io.StringIO())):
                path = os.path.join(tmp, "agy")
                image = bytearray(_minimal_macho())
                image[0x200:0x204] = b"ORIG"
                _write(path, image)
                with (mock.patch.dict(manager.SPEC, {target: spec}),
                      mock.patch.object(manager, "_mac_sign_transaction",
                                        side_effect=OSError("fixture signing failure"))):
                    self.assertEqual(manager._mac_run_patch([target], {target: path}), 1)
                self.assertEqual(spec["status"](path)[0], "unpatched")
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), bytes(image))

    def test_macos_patch_automatically_removes_quarantine_after_signing(self):
        gate = manager.Gate(b"ORIG", b"DONE", b"DONE")
        spec = {
            "name": "Fixture CLI",
            "find": lambda: [],
            "status": lambda path: manager.gate_status(path, gate),
            "patch": lambda path: manager.gate_patch(path, gate, "Fixture", "agy"),
        }
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "agy")
            image = bytearray(_minimal_macho())
            image[0x200:0x204] = b"ORIG"
            _write(path, image)
            with (mock.patch.dict(manager.SPEC, {"cli": spec}),
                  mock.patch.object(manager, "_mac_sign_transaction") as sign,
                  mock.patch.object(manager, "_mac_remove_quarantine") as quarantine):
                self.assertEqual(manager._mac_run_patch(["cli"], {"cli": path}), 0)
            sign.assert_called_once_with({"cli": path})
            quarantine.assert_called_once_with({"cli": path})

    def test_macos_quarantine_removal_covers_bundle_recursively(self):
        attribute = "com.apple.quarantine"
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            app, main, _, _, main_js = _mac_app(tmp)
            values = {app: b"root-value", main: b"nested-value"}
            removed = []

            def listxattr(path, follow_symlinks=False):
                return [attribute] if path in values else []

            def getxattr(path, name, follow_symlinks=False):
                self.assertEqual(name, attribute)
                return values[path]

            def removexattr(path, name, follow_symlinks=False):
                self.assertEqual(name, attribute)
                removed.append(path)

            with (mock.patch.object(manager.os, "listxattr", side_effect=listxattr, create=True),
                  mock.patch.object(manager.os, "getxattr", side_effect=getxattr, create=True),
                  mock.patch.object(manager.os, "removexattr", side_effect=removexattr, create=True),
                  mock.patch.object(manager.os, "setxattr", create=True)):
                manager._mac_remove_quarantine({"ide": main_js})

            self.assertCountEqual(removed, [app, main])

    def test_macos_flow_is_dispatched_only_on_darwin(self):
        with (mock.patch.object(manager.sys, "platform", "linux"),
              mock.patch.object(manager, "_mac_run_patch") as mac_patch):
            self.assertEqual(manager.run("patch", [], {}), 0)
            mac_patch.assert_not_called()
        with (mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch.object(manager, "_mac_run_patch", return_value=7) as mac_patch):
            self.assertEqual(manager.run("patch", [], {}), 7)
            mac_patch.assert_called_once_with([], {})

    def test_macos_xattr_fallback_preserves_bytes_and_checks_errors(self):
        value = b"\x00\xff\nquarantine"
        path = os.path.abspath("file with spaces")
        attr = "com.apple.quarantine"
        with (mock.patch.object(manager.os, "listxattr", None, create=True),
              mock.patch.object(manager.os, "getxattr", None, create=True),
              mock.patch.object(manager.os, "setxattr", None, create=True),
              mock.patch.object(manager.os, "removexattr", None, create=True),
              mock.patch.object(manager, "_mac_command") as command):
            command.return_value.stdout = attr + "\n"
            self.assertEqual(manager._mac_xattr("list", path), [attr])
            command.return_value.stdout = value.hex() + "\n"
            self.assertEqual(manager._mac_xattr("get", path, attr), value)
            manager._mac_xattr("set", path, attr, value)
            manager._mac_xattr("remove", path, attr)
            self.assertEqual(command.call_args_list, [
                mock.call(["/usr/bin/xattr", "-s", path]),
                mock.call(["/usr/bin/xattr", "-s", "-p", "-x", attr, path]),
                mock.call(["/usr/bin/xattr", "-s", "-w", "-x", attr, value.hex(), path]),
                mock.call(["/usr/bin/xattr", "-s", "-d", attr, path]),
            ])
            command.side_effect = OSError("permission denied")
            with self.assertRaises(OSError):
                manager._mac_xattr("list", path)

    def test_macos_quarantine_failure_restores_removed_attributes(self):
        attr = "com.apple.quarantine"
        value = b"\x00\xff\noriginal"
        with tempfile.TemporaryDirectory() as tmp:
            paths = [os.path.realpath(os.path.join(tmp, name)) for name in ("one", "two")]
            for path in paths:
                _write(path, b"fixture")
            def operation(action, path, attribute=None, data=None):
                if action == "list": return [attr]
                if action == "get": return value
                if action == "remove" and path == paths[1]:
                    raise OSError("permission denied")
            with mock.patch.object(manager, "_mac_xattr", side_effect=operation) as xattr:
                with self.assertRaises(OSError):
                    manager._mac_remove_quarantine(dict(zip(("cli", "manager"), paths)))
                self.assertEqual(xattr.call_args_list[-1],
                                 mock.call("set", paths[0], attr, value))


if __name__ == "__main__":
    unittest.main()
