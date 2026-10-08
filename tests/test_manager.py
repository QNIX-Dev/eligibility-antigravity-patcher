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


class DesktopProfileTests(unittest.TestCase):
    @staticmethod
    def token_binary():
        # Real ARM64 2.19.1 constructor bytes; relocate only its ADRP for this
        # minimal Mach-O fixture. The fallback string is code, not a credential.
        code = bytes.fromhex("03000090 63c83d91 a40380d2 e39306a9 e0230191 e10740b2 e20301aa 4791ac97 e18303a9")
        image = bytearray(_minimal_macho(0x0100000C))
        image.extend(b"\0" * (0x1000 - len(image)))
        struct.pack_into("<QQQQ", image, 32 + 24, 0, len(image), 0, len(image))
        struct.pack_into("<Q", image, 32 + 72 + 40, len(code))
        image[0x200:0x200 + len(code)] = code
        image[0xf72:0xf72 + 29] = b"jetski-standalone-oauth-token"
        return image

    @staticmethod
    def fixture(tmp):
        app, _, _, server, _ = _mac_app(tmp)
        _write(server, DesktopProfileTests.token_binary())
        info = os.path.join(app, "Contents", "Info.plist")
        with open(info, "rb") as f:
            plist = plistlib.load(f)
        plist["CFBundleShortVersionString"] = "2.19.1"
        plist["CFBundleIdentifier"] = "com.google.antigravity"
        plist["CFBundleName"] = "Antigravity"
        with open(info, "wb") as f:
            plistlib.dump(plist, f)
        header = {"files": {"dist": {"files": {}}}}
        scripts = {
            "dist/main.js": 'const lock = electron_1.app.requestSingleInstanceLock();',
            "dist/paths.js": "\n".join("path_1.default.join(os_1.default.homedir(), '.gemini', 'fixture');" for _ in range(5)),
            "dist/languageServer.js": "        // Point the LS at the main process' host bridge server.\n"
                                      "        env['AGY_BROWSER_ACTIVE_PORT_FILE'] = (0, paths_1.getActivePortFilePath)();",
            "dist/updater.js": "\n".join("function " + name + "() {}" for name in
                ("initAutoUpdater", "checkForUpdates", "quitAndInstall", "applyHostUpdate", "setAutoUpdateChecking")),
        }
        for name in scripts:
            header["files"]["dist"]["files"][name.split("/")[1]] = {"offset": "0", "size": 0}
        archive = os.path.join(app, "Contents", "Resources", "app.asar")
        manager._asar_write(archive, header, b"", scripts)
        return app, server, archive

    def test_create_profiles_preserves_source_and_separates_all_storage(self):
        with (tempfile.TemporaryDirectory() as tmp,
              contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(manager, "_desktop_profiles_root", return_value=os.path.join(tmp, "profiles")),
              mock.patch.object(manager, "_desktop_profile_sign") as sign):
            source, server, archive = self.fixture(tmp)
            with open(archive, "rb") as f:
                original = f.read()
            for name in ("work", "personal"):
                self.assertEqual(manager.desktop_profile_create(name, {"manager": server}), 0)
                profile = manager._desktop_profile_path(name)
                if os.name == "posix":
                    self.assertEqual(os.stat(profile).st_mode & 0o777, 0o700)
                copied = os.path.join(profile, "Antigravity.app")
                with open(os.path.join(copied, "Contents", "Info.plist"), "rb") as f:
                    plist = plistlib.load(f)
                self.assertEqual(plist["CFBundleIdentifier"], "com.parsa.agy-profile." + name)
                self.assertEqual(plist["CFBundleName"], "Antigravity")
                self.assertEqual(plist["CFBundleURLTypes"][0]["CFBundleURLSchemes"], ["antigravity-profile-" + name])
                header, payload = manager._asar_read(os.path.join(copied, "Contents", "Resources", "app.asar"))
                main = manager._asar_content(header, payload, "dist/main.js")
                self.assertLess(main.index("setPath"), main.index("requestSingleInstanceLock"))
                paths = manager._asar_content(header, payload, "dist/paths.js")
                self.assertNotIn("os_1.default.homedir()", paths)
                ls = manager._asar_content(header, payload, "dist/languageServer.js")
                self.assertIn('"--gemini_dir"', ls)
                self.assertIn('"--local_chrome_user_data_dir"', ls)
                self.assertIn('env["SSH_CONNECTION"]', ls)
                self.assertEqual(manager._asar_content(header, payload, "dist/updater.js").count("return; // Profile"), 5)
            self.assertEqual(sign.call_count, 2)
            with open(archive, "rb") as f:
                self.assertEqual(f.read(), original)
            with self.assertRaises(ValueError):
                manager.desktop_profile_create("work", {"manager": server})

    def test_failed_signing_never_publishes_profile_and_cleans_temporary_copy(self):
        with (tempfile.TemporaryDirectory() as tmp,
              contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(manager, "_desktop_profiles_root", return_value=os.path.join(tmp, "profiles")),
              mock.patch.object(manager, "_desktop_profile_sign", side_effect=OSError("fixture signing failure"))):
            _, server, _ = self.fixture(tmp)
            with self.assertRaises(OSError):
                manager.desktop_profile_create("work", {"manager": server})
            self.assertEqual(os.listdir(manager._desktop_profiles_root()), [])

    def test_unknown_build_and_archive_layout_fail_before_copying(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_desktop_profiles_root", return_value=os.path.join(tmp, "profiles")),
              mock.patch.object(manager.shutil, "copytree") as copy):
            app, server, archive = self.fixture(tmp)
            header, payload = manager._asar_read(archive)
            manager._asar_write(archive, header, payload, {"dist/main.js": "unsupported fixture"})
            with self.assertRaises(ValueError):
                manager.desktop_profile_create("work", {"manager": server})
            copy.assert_not_called()
            self.assertFalse(os.path.exists(manager._desktop_profiles_root()))

    def test_profile_names_and_symlinks_cannot_escape_storage_root(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp)):
            for name in ("../escape", "", "Work", "/absolute", "has space", "a" * 49):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    manager._desktop_profile_path(name)
            os.symlink(os.path.dirname(tmp), os.path.join(tmp, "work"))
            with self.assertRaises(ValueError):
                manager._desktop_profile_path("work")

    def test_open_uses_profile_executable_and_private_process_permissions(self):
        with (tempfile.TemporaryDirectory() as tmp,
              contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp),
              mock.patch.object(manager.subprocess, "Popen") as launch):
            profile = os.path.join(tmp, "work")
            os.mkdir(profile)
            app, _, _, _, _ = _mac_app(profile)
            path = os.path.join(app, "Contents", "Resources", "bin", "language_server")
            _write(path, self.token_binary())
            manager._desktop_namespace_credentials(path, profile)
            launch.return_value.wait.return_value = 0
            self.assertEqual(manager.desktop_profile_open("work"), 0)
            self.assertEqual(os.path.realpath(launch.call_args.args[0][0]), manager._mac_bundle_main(app))
            self.assertEqual(launch.call_args.kwargs["umask"], 0o077)
            self.assertTrue(launch.call_args.kwargs["start_new_session"])

    def test_root_is_refused_and_macos_route_preserves_override(self):
        with (contextlib.redirect_stdout(io.StringIO()), mock.patch.object(manager.os, "geteuid", return_value=0, create=True)):
            self.assertEqual(manager.run_desktop_accounts(["list"]), 2)
        with (mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch.object(manager, "run_desktop_accounts", return_value=0) as run):
            overrides = {"manager": "/custom/server"}
            self.assertEqual(manager.run_accounts(["manager", "open", "work"], overrides), 0)
            run.assert_called_once_with(["open", "work"], overrides)

    def test_profile_signing_uses_matching_bundle_identifiers_and_skips_main_until_last(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_mac_codesign") as sign,
              mock.patch.object(manager, "_mac_library_validation_entitlements", return_value=None)):
            app, server, _ = self.fixture(tmp)
            _write(server, _minimal_macho())
            manager._desktop_profile_sign(app)
            self.assertEqual(sign.call_args_list, [mock.call(server),
                mock.call(app, bundle=True, entitlements=None, identifier="com.google.antigravity")])

    def test_copied_helper_identity_and_loading_entitlements_remain_compatible(self):
        with (tempfile.TemporaryDirectory() as tmp,
              contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(manager, "_desktop_profiles_root", return_value=os.path.join(tmp, "profiles")),
              mock.patch.object(manager, "_mac_codesign") as sign,
              mock.patch.object(manager, "_mac_entitlements", return_value={}),
              mock.patch.object(manager, "_mac_library_validation_entitlements", return_value=None)):
            app, server, _ = self.fixture(tmp)
            framework_dir = os.path.join(app, "Contents", "Frameworks")
            os.mkdir(framework_dir)
            helper, _, _, _, _ = _mac_app(framework_dir)
            helper_info = os.path.join(helper, "Contents", "Info.plist")
            with open(helper_info, "rb") as f:
                plist = plistlib.load(f)
            plist.update(CFBundleIdentifier="com.google.antigravity.helper.GPU", ElectronTeamID="fixture-team")
            with open(helper_info, "wb") as f:
                plistlib.dump(plist, f)
            self.assertEqual(manager.desktop_profile_create("work", {"manager": server}), 0)
            copied_helper = os.path.join(manager._desktop_profile_path("work"), "Antigravity.app", "Contents", "Frameworks", "Antigravity.app")
            with open(os.path.join(copied_helper, "Contents", "Info.plist"), "rb") as f:
                plist = plistlib.load(f)
            self.assertEqual(plist["CFBundleIdentifier"], "com.parsa.agy-profile.work.helper.GPU")
            self.assertNotIn("ElectronTeamID", plist)
            helper_call = next(c for c in sign.call_args_list if c.kwargs.get("identifier", "").endswith("helper.GPU"))
            self.assertTrue(helper_call.kwargs["entitlements"][manager.MAC_DISABLE_LIBRARY_VALIDATION])
            self.assertTrue(helper_call.kwargs["entitlements"]["com.apple.security.cs.allow-jit"])

    def test_archive_corruption_is_rejected_before_script_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, archive = self.fixture(tmp)
            header, payload = manager._asar_read(archive)
            damaged = bytearray(payload)
            damaged[0] ^= 1
            with self.assertRaises(ValueError):
                manager._asar_content(header, damaged, "dist/main.js")

    def test_real_token_constructor_recognizes_both_states(self):
        original = bytes.fromhex("c39400d0 63c83d91 a40380d2 e39306a9 e0230191 e10740b2 e20301aa 4791ac97 e18303a9")
        gate = manager.DESKTOP_TOKEN_GATE_ARM64
        self.assertEqual(gate.find(original)[0], "unpatched")
        patched = original[:8] + gate.fix + original[12:]
        self.assertEqual(gate.find(patched)[0], "patched")
        with self.assertRaises(manager.SignatureAmbiguous):
            gate.find(original + original)

    def test_credentials_are_namespaced_without_touching_shared_login_or_user_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "server")
            _write(path, self.token_binary())
            profile = os.path.join(tmp, "work")
            manager._desktop_namespace_credentials(path, profile)
            manager._desktop_namespace_credentials(path, profile, check_only=True)
            with open(path, "rb") as f:
                data = f.read()
            self.assertEqual(data[0xf72:0xf72 + 29], manager._desktop_token_name(profile) + b"\0")
            with self.assertRaises(ValueError):
                manager._desktop_namespace_credentials(path, os.path.join(tmp, "personal"), check_only=True)
            self.assertEqual(manager.gate_status(path, manager.DESKTOP_TOKEN_GATE_ARM64)[0], "patched")

    def test_credential_constructor_failures_do_not_write(self):
        for change in ("missing", "duplicate", "wrong_literal", "nonexecutable"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                data = self.token_binary()
                if change == "missing":
                    data[0x200] = 0
                elif change == "duplicate":
                    data[0x224:0x248] = data[0x200:0x224]
                    struct.pack_into("<Q", data, 32 + 72 + 40, 72)
                elif change == "wrong_literal":
                    data[0xf72] = 0
                else:
                    struct.pack_into("<Q", data, 32 + 72 + 40, 0)
                path = os.path.join(tmp, "server")
                _write(path, data)
                with self.assertRaises((ValueError, manager.SignatureNotFound, manager.SignatureAmbiguous)):
                    manager._desktop_namespace_credentials(path, tmp)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), data)

    def test_repair_rolls_back_app_swap_when_final_verification_fails(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp),
              mock.patch.object(manager.subprocess, "run", return_value=mock.Mock(stdout="")),
              mock.patch.object(manager, "_desktop_profile_sign")):
            profile = os.path.join(tmp, "work")
            os.mkdir(profile)
            app, _, _, server, _ = _mac_app(profile)
            original = self.token_binary()
            _write(server, original)
            real = manager._desktop_namespace_credentials

            def fail_final(path, profile, check_only=False):
                if os.path.realpath(path) == server and check_only:
                    raise ValueError("final app verification failed")
                return real(path, profile, check_only)

            with mock.patch.object(manager, "_desktop_namespace_credentials", side_effect=fail_final):
                with self.assertRaisesRegex(ValueError, "final app verification"):
                    manager.desktop_profile_repair("work")
            with open(server, "rb") as f:
                self.assertEqual(f.read(), original)
            self.assertEqual(os.listdir(profile), ["Antigravity.app"])

    def test_credential_patch_rolls_back_failed_final_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "server")
            original = self.token_binary()
            _write(path, original)
            real = manager._desktop_token_location
            calls = 0

            def fail_final(*args):
                nonlocal calls
                calls += 1
                if calls == 5:
                    raise ValueError("final verification failed")
                return real(*args)

            with mock.patch.object(manager, "_desktop_token_location", side_effect=fail_final):
                with self.assertRaisesRegex(ValueError, "final verification"):
                    manager._desktop_namespace_credentials(path, tmp)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)

    def test_repair_preserves_profile_data_and_original_on_sign_failure(self):
        for fail in (False, True):
            with (self.subTest(sign_failure=fail), tempfile.TemporaryDirectory() as tmp,
                  mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp),
                  mock.patch.object(manager.subprocess, "run", return_value=mock.Mock(stdout="")),
                  mock.patch.object(manager, "_desktop_profile_sign", side_effect=OSError("sign failed") if fail else None),
                  contextlib.redirect_stdout(io.StringIO())):
                profile = os.path.join(tmp, "work")
                os.mkdir(profile)
                app, _, _, server, _ = _mac_app(profile)
                original = self.token_binary()
                _write(server, original)
                data = os.path.join(profile, "user-data")
                os.mkdir(data)
                marker = os.path.join(data, "history")
                _write(marker, b"private fixture history")
                if fail:
                    with self.assertRaisesRegex(OSError, "sign failed"):
                        manager.desktop_profile_repair("work")
                    with open(server, "rb") as f:
                        self.assertEqual(f.read(), original)
                else:
                    self.assertEqual(manager.desktop_profile_repair("work"), 0)
                    manager._desktop_namespace_credentials(server, profile, check_only=True)
                with open(marker, "rb") as f:
                    self.assertEqual(f.read(), b"private fixture history")
                self.assertEqual(sorted(os.listdir(profile)), ["Antigravity.app", "user-data"])

    def test_repair_refuses_running_profile_before_copying(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp),
              mock.patch.object(manager.shutil, "copytree") as copy):
            profile = os.path.join(tmp, "work")
            os.mkdir(profile)
            app, executable, _, _, _ = _mac_app(profile)
            with mock.patch.object(manager.subprocess, "run", return_value=mock.Mock(stdout=os.path.join(profile, "Antigravity.app", "Contents", "MacOS", "Antigravity"))):
                with self.assertRaisesRegex(ValueError, "close this extra"):
                    manager.desktop_profile_repair("work")
            copy.assert_not_called()

    def test_legacy_profile_open_refuses_to_load_shared_credentials(self):
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager, "_desktop_profiles_root", return_value=tmp),
              mock.patch.object(manager.subprocess, "Popen") as launch):
            profile = os.path.join(tmp, "work")
            os.mkdir(profile)
            app, _, _, _, _ = _mac_app(profile)
            _write(os.path.join(app, "Contents", "Resources", "bin", "language_server"), self.token_binary())
            with self.assertRaisesRegex(ValueError, "repair"):
                manager.desktop_profile_open("work")
            launch.assert_not_called()


class TransactionTests(unittest.TestCase):
    def test_macos_signed_inode_denial_uses_replacement_for_patch_and_restore(self):
        gate = manager.Gate(rb"ORIG", rb"DONE", b"DONE", arch="arm64")
        status = lambda path: manager.gate_status(path, gate)
        real_open = open
        with (tempfile.TemporaryDirectory() as tmp,
              mock.patch.object(manager.sys, "platform", "darwin"),
              contextlib.redirect_stdout(io.StringIO())):
            path = os.path.realpath(os.path.join(tmp, "language_server"))
            original = bytearray(_minimal_macho(0x0100000C))
            original[0x200:0x204] = b"ORIG"
            _write(path, original)
            os.chmod(path, 0o755)
            link = os.path.join(tmp, "linked-server")
            os.symlink(path, link)

            def deny_installed_write(filename, mode="r", *args, **kwargs):
                if os.path.realpath(filename) == path and any(c in mode for c in "+wa"):
                    raise PermissionError(errno.EPERM, "Operation not permitted", path)
                return real_open(filename, mode, *args, **kwargs)

            inode = os.stat(path).st_ino
            with mock.patch("builtins.open", side_effect=deny_installed_write):
                self.assertTrue(manager.gate_patch(link, gate, "Fixture", "language_server"))
                self.assertEqual(status(link)[0], "patched")
                self.assertNotEqual(os.stat(path).st_ino, inode)
                self.assertTrue(manager.restore_file(link, status))
                self.assertEqual(status(link)[0], "unpatched")
            self.assertTrue(os.path.islink(link))
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original)
            self.assertFalse(any(name.startswith(".agy-write-") for name in os.listdir(tmp)))

    def test_macos_directory_denial_does_not_attempt_patch_or_backup(self):
        with (mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch("builtins.open", side_effect=PermissionError(errno.EPERM, "denied")),
              mock.patch.object(manager.tempfile, "mkstemp", side_effect=PermissionError(errno.EACCES, "denied")),
              mock.patch.object(manager, "make_backup") as backup,
              contextlib.redirect_stdout(io.StringIO())):
            self.assertFalse(manager.gate_patch("/fixture", manager.Gate(rb"ORIG", rb"DONE", b"DONE"),
                                                "Fixture", "fixture"))
        backup.assert_not_called()

    def test_macos_app_management_denial_explains_privacy_permission_even_as_root(self):
        with (mock.patch.object(manager.sys, "platform", "darwin"),
              mock.patch.object(manager.os, "geteuid", return_value=0, create=True),
              mock.patch.object(manager, "_mac_app_bundle", return_value="/Applications/Fixture.app"),
              mock.patch("builtins.open", side_effect=PermissionError(errno.EPERM, "Operation not permitted")),
              mock.patch.object(manager.tempfile, "mkstemp", side_effect=PermissionError(errno.EPERM, "directory denied")),
              mock.patch.object(manager, "make_backup") as backup,
              contextlib.redirect_stdout(io.StringIO()) as output):
            self.assertFalse(manager.gate_patch("/Applications/Fixture.app/Contents/MacOS/fixture",
                                                manager.Gate(rb"ORIG", rb"DONE", b"DONE"), "Fixture", "fixture"))
        backup.assert_not_called()
        self.assertIn("Privacy & Security > App Management", output.getvalue())
        self.assertIn("sudo does not grant", output.getvalue())
        self.assertIn("directory denied", output.getvalue())
        self.assertNotIn("use an account with write access", output.getvalue())

    def test_macos_staging_and_replacement_failures_preserve_installed_inode(self):
        for fix in (b"FAIL", b"DONE"):
            with (self.subTest(fix=fix), tempfile.TemporaryDirectory() as tmp,
                  mock.patch.object(manager.sys, "platform", "darwin"),
                  contextlib.redirect_stdout(io.StringIO())):
                path = os.path.join(tmp, "language_server")
                original = bytearray(_minimal_macho(0x0100000C))
                original[0x200:0x204] = b"ORIG"
                _write(path, original)
                inode = os.stat(path).st_ino
                gate = manager.Gate(rb"ORIG", rb"DONE", fix, arch="arm64")
                with mock.patch.object(manager.os, "replace", side_effect=PermissionError(errno.EPERM, "denied")) as replace:
                    self.assertFalse(manager.gate_patch(path, gate, "Fixture", "language_server"))
                self.assertEqual(replace.call_count, int(fix == b"DONE"))
                self.assertEqual(os.stat(path).st_ino, inode)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), original)
                self.assertFalse(any(name.startswith(".agy-write-") for name in os.listdir(tmp)))

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
            _write(agy, _minimal_macho())
            calls = []

            def record(path, bundle=False):
                calls.append((path, bundle))

            with (mock.patch.object(manager, "_mac_codesign", side_effect=record),
                  contextlib.redirect_stdout(io.StringIO())):
                manager._mac_sign_transaction(
                    {"cli": agy, "manager": language_server, "ide": main_js})

            self.assertEqual(calls, [(agy, False), (language_server, False), (app, True)])

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
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            path = os.path.join(tmp, "agy")
            original = _minimal_macho()
            image = bytearray(original)
            image[0x200:0x204] = b"ORIG"
            _write(path, image)
            with (mock.patch.dict(manager.SPEC, {"cli": spec}),
                  mock.patch.object(manager, "_mac_sign_transaction",
                                    side_effect=OSError("fixture signing failure"))):
                self.assertEqual(manager._mac_run_patch(
                    ["cli"], {"cli": path}), 1)
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
