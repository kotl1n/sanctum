import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from install import CONFIG, PLUGIN, STATE, Installer, atomic, encoded, safe_path, snapshot
from manage_backend import Invalid, check, load, set_enabled
from platform_support import WINDOWS, PLATFORM, LAUNCHER, executable, file_mode
from platform_support import reparse


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        patch_bytes = b"synthetic patch\n"
        ident = hashlib.sha256(patch_bytes).hexdigest()
        manifest = {"commit": "synthetic-commit", "patch_sha256": ident,
                    "code_mode_host_sha256": hashlib.sha256(b"helper").hexdigest()}
        binaries = {executable("codex"): hashlib.sha256(b"backend").hexdigest(),
                    executable("codex-code-mode-host"): manifest["code_mode_host_sha256"]}
        files = {
            "backend/" + executable("codex"): b"backend", "backend/" + executable("codex-code-mode-host"): b"helper",
            "backend/native.patch": patch_bytes, "backend/manifest.json": encoded(manifest),
            "backend/build-info.json": encoded({"commit": manifest["commit"], "binaries": binaries}),
            "plugin/bin/" + executable("sanctum-guard"): b"guard", "plugin/bin/" + executable("sanctum-codex"): b"adapter",
            "plugin/.codex-plugin/plugin.json": encoded({"name": "sanctum-portless"}),
            "plugin/hooks/hooks.json": encoded({"hooks": {}}),
            "plugin/policy.json": encoded({"literals": []}),
            "plugin/ui/composer.js": b"// composer", "plugin/ui/composer-host.cjs": b"// host",
            "plugin/ui/manage_backend.py": b"# manager",
            "plugin/ui/cli_text.py": b"# cli translations",
            "plugin/ui/platform_support.py": b"# platform operations",
        }
        self.profile = {"schema": 1, "commit": manifest["commit"], "desktop": {},
                        "backends": {ident: {"binaries": binaries, "features": ["typed_compaction_replay"]}},
                        "plugin": {n: hashlib.sha256(files["plugin/bin/" + n]).hexdigest()
                                   for n in (executable("sanctum-guard"), executable("sanctum-codex"))},
                        "ui": {n: hashlib.sha256(files["plugin/ui/" + n]).hexdigest()
                               for n in ("composer.js", "composer-host.cjs", "manage_backend.py", "cli_text.py", "platform_support.py")}}
        if WINDOWS:
            for name in ('app.exe', 'node.exe', 'codex.exe', 'helper.exe', 'app.asar'):
                (self.root / name).write_bytes(b'synthetic desktop component')
            self.profile['desktop'] = {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest() for name in ('app.exe', 'node.exe', 'codex.exe', 'helper.exe', 'app.asar')}
            self.profile['launch'] = {'app':'app.exe', 'node':'node.exe', 'codex':'codex.exe', 'code_mode_host':'helper.exe', 'archive':'app.asar'}
            self.profile['supported'] = {'platform':PLATFORM, 'reviewed':True}
            root_patch = patch('install.installed_desktop_root', return_value=self.root)
            root_patch.start()
            self.addCleanup(root_patch.stop)
        files["plugin/ui/desktop-compatibility.json"] = encoded(self.profile)
        for relative, data in files.items():
            atomic(self.bundle / relative, data)
        self.files = {p: hashlib.sha256(data).hexdigest() for p, data in files.items()}
        self.write_release()

    def write_release(self):
        atomic(self.bundle / "release.json", encoded({"schema": 1, "files": self.files}))

    def test_install_plan_apply_check_uninstall(self):
        with Installer(self.home) as installer:
            self.assertEqual(installer.install(self.bundle)["status"], "plan")
            self.assertFalse((self.home / PLUGIN).exists())
            result = installer.install(self.bundle, apply=True)
            self.assertEqual(result["status"], "staged")
            self.assertFalse(load(self.home / CONFIG / "settings.json")["enabled"])
            self.assertTrue(check(self.home, self.profile, self.root)["compatible"])
            self.assertEqual(snapshot(self.home / PLUGIN / "bin" / executable("sanctum-guard"))["mode"], file_mode(0o755))
            self.assertEqual(installer.uninstall(apply=True)["status"], "removed")
            self.assertFalse((self.home / PLUGIN / "bin" / executable("sanctum-guard")).exists())
            self.assertFalse((self.home / STATE / "installed.json").exists())

    def test_atomic_preserves_readonly_attribute(self):
        path = self.home / "readonly"
        atomic(path, b"fixture", 0o444)
        self.assertEqual(snapshot(path)["mode"], file_mode(0o444))

    def test_rollback_restores_previous_content_and_modes(self):
        path = self.home / "existing"
        atomic(path, b"original", 0o640)
        with Installer(self.home) as installer:
            transaction = installer.transact([(Path("existing"), b"changed", 0o600),
                                               (Path("new"), b"new", 0o644)])
            installer.rollback(transaction)
        self.assertEqual(path.read_bytes(), b"original")
        self.assertEqual(snapshot(path)["mode"], file_mode(0o640))
        self.assertFalse((self.home / "new").exists())

    def test_upgrade_from_local_version_and_rollback_restore_previous_launcher(self):
        previous_plugin = PLUGIN.with_name('0.1.1')
        with Installer(self.home) as installer:
            with patch('install.PLUGIN', previous_plugin):
                installer.install(self.bundle, True)
            launcher_path = self.home / (LAUNCHER.with_suffix(".ps1") if WINDOWS else LAUNCHER)
            previous_launcher = launcher_path.read_bytes()
            upgrade = installer.install(self.bundle, True)
            self.assertTrue((self.home / PLUGIN / 'bin' / executable('sanctum-guard')).exists())
            self.assertTrue((self.home / previous_plugin / 'bin' / executable('sanctum-guard')).exists())
            self.assertIn(str(PLUGIN / 'ui/composer-host.cjs'), launcher_path.read_text(encoding="utf-8"))
            installer.rollback(upgrade['transaction'])
            self.assertFalse((self.home / PLUGIN / 'bin' / executable('sanctum-guard')).exists())
            self.assertTrue((self.home / previous_plugin / 'bin' / executable('sanctum-guard')).exists())
            self.assertEqual(launcher_path.read_bytes(), previous_launcher)

    def test_pending_transaction_recovers_after_interruption(self):
        with Installer(self.home) as installer:
            installer.transact([(Path("new"), b"new", 0o600)])
            transaction = next((self.home / STATE).glob("transaction-*.json"))
            atomic(self.home / STATE / "pending.json", transaction.read_bytes())
        with Installer(self.home):
            self.assertFalse((self.home / "new").exists())
            self.assertFalse((self.home / STATE / "pending.json").exists())

    def test_modified_binary_blocks_uninstall_and_rollback(self):
        with Installer(self.home) as installer:
            result = installer.install(self.bundle, apply=True)
            path = self.home / PLUGIN / "bin" / executable("sanctum-guard")
            atomic(path, b"local edit", 0o755)
            for action in (lambda: installer.uninstall(True),
                           lambda: installer.rollback(result["transaction"])):
                with self.assertRaises(Invalid):
                    action()
                self.assertEqual(path.read_bytes(), b"local edit")

    def test_user_settings_and_policy_survive_uninstall(self):
        with Installer(self.home) as installer:
            installer.install(self.bundle, apply=True)
            for name, content in (("settings.json", {"enabled": True}),
                                  ("policy.json", {"literals": ["private-project"]})):
                atomic(self.home / CONFIG / name, encoded(content))
            installer.uninstall(apply=True)
        self.assertTrue(load(self.home / CONFIG / "settings.json")["enabled"])
        self.assertEqual(load(self.home / CONFIG / "policy.json")["literals"], ["private-project"])

    def test_corrupt_bundle_is_rejected_before_installation(self):
        atomic(self.bundle / "plugin/bin" / executable("sanctum-guard"), b"tampered")
        with Installer(self.home) as installer, self.assertRaises(Invalid):
            installer.install(self.bundle, apply=True)
        self.assertFalse((self.home / PLUGIN).exists())

    def test_incomplete_bundle_is_rejected(self):
        del self.files["plugin/ui/composer-host.cjs"]
        self.write_release()
        with Installer(self.home) as installer, self.assertRaises(Invalid):
            installer.install(self.bundle, apply=True)
        self.assertFalse((self.home / PLUGIN).exists())

    def test_paths_and_symlinks_cannot_escape_home(self):
        linked = self.home / "linked"
        if WINDOWS:
            subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(linked), str(self.root)],
                           check=True, stdout=subprocess.DEVNULL)
        else:
            linked.symlink_to(self.root, target_is_directory=True)
        self.assertTrue(reparse(linked))
        for path in ("../outside", "/tmp/outside", "linked/outside"):
            with self.assertRaises(Invalid):
                safe_path(self.home, path)
        self.assertFalse((self.root / "outside").exists())

    def test_duplicate_json_metadata_is_rejected(self):
        atomic(self.bundle / "release.json", b'{"schema":1,"schema":1,"files":{}}')
        with Installer(self.home) as installer, self.assertRaisesRegex(Invalid, "duplicate_json_field"):
            installer.install(self.bundle)

    def test_compatibility_changes_fail_closed(self):
        with Installer(self.home) as installer:
            installer.install(self.bundle, apply=True)
        atomic(self.home / PLUGIN / "ui/composer.js", b"changed")
        self.assertFalse(check(self.home, self.profile, self.root)["compatible"])

    def test_enable_requires_compatible_install_and_disable_still_works(self):
        with Installer(self.home) as installer:
            installer.install(self.bundle, apply=True)
        self.assertEqual(set_enabled(self.home, self.profile, True)['status'], 'plan')
        self.assertFalse(load(self.home / CONFIG / 'settings.json')['enabled'])
        set_enabled(self.home, self.profile, True, apply=True)
        self.assertTrue(load(self.home / CONFIG / 'settings.json')['enabled'])
        atomic(self.home / PLUGIN / 'ui/composer.js', b'changed')
        with self.assertRaisesRegex(Invalid, 'desktop_incompatible'):
            set_enabled(self.home, self.profile, True, apply=True)
        set_enabled(self.home, self.profile, False, apply=True)
        self.assertFalse(load(self.home / CONFIG / 'settings.json')['enabled'])


if __name__ == "__main__":
    unittest.main()
