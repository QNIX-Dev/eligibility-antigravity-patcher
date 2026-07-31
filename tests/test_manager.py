import contextlib
import io
import os
import struct
import tempfile
import unittest
from unittest import mock

import manager


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def _minimal_pe(code=b"", data=b""):
    # One executable and one data section.
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
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


def _minimal_elf():
    # One executable and one read-only segment.
    image = bytearray(0x200)
    image[:6] = b"\x7fELF\x02\x01"
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


def _minimal_macho():
    # One __TEXT,__text section.
    image = bytearray(0x300)
    image[:4] = b"\xcf\xfa\xed\xfe"
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

def _minimal_fat_macho():
    thin = _minimal_macho()
    image = bytearray(0x100 + len(thin))
    image[:4] = b"\xca\xfe\xba\xbe"
    struct.pack_into(">I", image, 4, 1)
    struct.pack_into(">IIIII", image, 8, 0x01000007, 3, 0x100, len(thin), 8)
    image[0x100:] = thin
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


class ExecutableRangeTests(unittest.TestCase):
    def _ranges(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixture")
            _write(path, payload)
            return manager.executable_ranges(path)

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
