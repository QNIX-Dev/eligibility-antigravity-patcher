import base64
import contextlib
import io
import json
import os
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


class GateStateTests(unittest.TestCase):
    def setUp(self):
        self.gate = manager.Gate(b"ORIG", b"DONE", b"DONE")

    def test_unique_original_and_patched_states(self):
        self.assertEqual(self.gate.find(b"xxORIGyy"), ("unpatched", 2))
        self.assertEqual(self.gate.find(b"xxDONEyy"), ("patched", 2))

    def test_duplicate_original_is_ambiguous(self):
        with self.assertRaises(manager.SignatureAmbiguous):
            self.gate.find(b"ORIG--ORIG")

    def test_duplicate_patched_is_ambiguous(self):
        with self.assertRaises(manager.SignatureAmbiguous):
            self.gate.find(b"DONE--DONE")

    def test_mixed_original_and_patched_is_ambiguous(self):
        with self.assertRaises(manager.SignatureAmbiguous):
            self.gate.find(b"ORIG--DONE")

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
        source = (
            b"\x48\x85\xc0\x0f\x84\x0d\x02\x00\x00"
            b"\x80\x78\x08\x00\x0f\x85\x03\x02\x00\x00"
            b"\xe8\x68\xf1\xfd\xff"
            b"\x48\x89\x84\x24\x80\x00\x00\x00"
            b"\x48\x89\x5c\x24\x50\x48\x89\x4c\x24\x70"
        )
        state, offset, gate = manager.CLI_GATE.resolve(source)
        self.assertEqual((state, offset, gate), ("unpatched", 9, manager.CLI_GATE_X64))
        patched = bytearray(source)
        patched[offset:offset + len(gate.fix)] = gate.fix
        self.assertEqual(manager.CLI_GATE.resolve(patched)[:2], ("patched", 9))

    def test_previous_cli_x64_signature_is_not_supported(self):
        previous = (
            b"\x48\x85\xc0\x0f\x84\xf6\x01\x00\x00"
            b"\x80\x78\x08\x00\x0f\x85\xec\x01\x00\x00"
            b"\xe8\x12\x34\x56\x78"
            b"\x48\x89\x44\x24\x78\x48\x89\x5c\x24\x48"
            b"\x48\x89\x4c\x24\x68"
        )
        with self.assertRaises(manager.SignatureNotFound):
            manager.CLI_GATE.resolve(previous)

    def test_current_cli_arm64_signature_and_patch(self):
        source = (
            b"\xe1\x18\x00\xb5"
            b"\xc0\x0d\x00\xb4"
            b"\x01\x20\x40\x39"
            b"\x81\x0d\x00\x37"
            b"\xbe\x94\xff\x97"
            b"\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9"
        )
        state, offset, gate = manager.CLI_GATE.resolve(source)
        self.assertEqual((state, offset, gate), ("unpatched", 8, manager.CLI_GATE_ARM64))
        patched = bytearray(source)
        patched[offset:offset + len(gate.fix)] = gate.fix
        self.assertEqual(manager.CLI_GATE.resolve(patched)[:2], ("patched", 8))

    def test_previous_cli_arm64_signature_is_not_supported(self):
        previous = (
            b"\xe1\x18\x00\xb5"
            b"\x80\x0d\x00\xb4"
            b"\x01\x20\x40\x39"
            b"\x41\x0d\x00\x37"
            b"\x35\x94\xff\x97"
            b"\xe0\x43\x00\xf9\xe1\x2b\x00\xf9\xe2\x3b\x00\xf9"
        )
        with self.assertRaises(manager.SignatureNotFound):
            manager.CLI_GATE.resolve(previous)

    def test_cli_arm64_signature_requires_outer_registers(self):
        wrong_outer_register = (
            b"\xe2\x18\x00\xb5"
            b"\xc0\x0d\x00\xb4"
            b"\x01\x20\x40\x39"
            b"\x81\x0d\x00\x37"
            b"\xbe\x94\xff\x97"
            b"\xe0\x4b\x00\xf9\xe1\x33\x00\xf9\xe2\x43\x00\xf9"
        )
        with self.assertRaises(manager.SignatureNotFound):
            manager.CLI_GATE.resolve(wrong_outer_register)

    def test_manager_arm64_old_and_new_signatures_patch(self):
        old = (
            b"\x03\x20\x40\x39"
            b"\xc3\x01\x00\x36"
            b"\xe3\x03\x40\xf9\xe4\x13\x48\xa9"
            b"\x03\x10\x06\xa9"
        )
        current = (
            b"\x03\x20\x40\x39"
            b"\xa3\x01\x00\x36"
            b"\xe3\x13\x48\xa9"
            b"\x03\x10\x06\xa9"
        )
        for source in (old, current):
            with self.subTest(source=source.hex()):
                state, offset, gate = manager.MANAGER_GATE.resolve(source)
                self.assertEqual((state, offset, gate),
                                 ("unpatched", 0, manager.MANAGER_GATE_ARM64))
                patched = bytearray(source)
                patched[offset:offset + len(gate.fix)] = gate.fix
                self.assertEqual(manager.MANAGER_GATE.resolve(patched)[:2], ("patched", 0))

    def test_manager_arm64_signature_requires_tbz_w3(self):
        wrong_register = (
            b"\x03\x20\x40\x39"
            b"\xa4\x01\x00\x36"
            b"\xe3\x13\x48\xa9"
            b"\x03\x10\x06\xa9"
        )
        with self.assertRaises(manager.SignatureNotFound):
            manager.MANAGER_GATE.resolve(wrong_register)


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

    def test_pe_ranges(self):
        self.assertEqual(self._ranges(_minimal_pe()), ((0x200, 0x240),))

    def test_elf_ranges(self):
        self.assertEqual(self._ranges(_minimal_elf()), ((0x100, 0x120),))

    def test_macho_ranges(self):
        self.assertEqual(self._ranges(_minimal_macho()), ((0x200, 0x220),))

    def test_fat_macho_ranges(self):
        self.assertEqual(self._ranges(_minimal_fat_macho()), ((0x300, 0x320),))

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


class TransactionTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
