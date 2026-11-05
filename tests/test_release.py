import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from build_release import compiler_environment, ensure_no_personal_paths
from manage_backend import Invalid, sha
from install import PLUGIN
from platform_support import WINDOWS, reparse
from package_release import release_version, source_archive


class ReleaseTests(unittest.TestCase):
    def test_release_versions_match_all_sanctum_components(self):
        version = release_version()
        self.assertEqual(version, '1.0.0')
        self.assertEqual(PLUGIN.name, version)
        lock_document = tomllib.loads(Path(ROOT, 'Cargo.lock').read_text(encoding="utf-8"))
        entries = [item for item in lock_document['package'] if item['name'] == 'sanctum']
        self.assertEqual(entries[0]['version'], version)

    def test_native_patch_matches_manifest_and_source_template_is_unsealed(self):
        base = ROOT / 'native/codex-0.159.0-context'
        manifest = json.loads((base / 'manifest.json').read_text(encoding="utf-8"))
        self.assertEqual(sha(base / 'native.patch'), manifest['patch_sha256'])
        profile = json.loads((ROOT / 'native/desktop-compatibility.json').read_text(encoding="utf-8"))
        self.assertEqual(profile['commit'], manifest['commit'])
        for name in ('plugin', 'ui', 'backends'):
            self.assertEqual(profile[name], {}, 'Build-specific hashes belong in the generated release profile')

    def test_compiler_environment_preserves_flags_and_remaps_paths(self):
        env = compiler_environment(base={'RUSTFLAGS': '-C debuginfo=0', 'CFLAGS': '-O2'})
        self.assertEqual(env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f')[:2], ['-C', 'debuginfo=0'])
        self.assertIn('--remap-path-prefix=' + str(ROOT) + '=/src/sanctum', env['CARGO_ENCODED_RUSTFLAGS'])
        self.assertIn('-O2', env['CFLAGS'])
        if not WINDOWS:
            self.assertIn('-ffile-prefix-map=', env['CFLAGS'])

    def test_binary_with_personal_build_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(b'ELF synthetic safe binary')
            ensure_no_personal_paths(path)
            path.write_bytes(b'ELF ' + str(ROOT).encode())
            with self.assertRaisesRegex(ValueError, 'personal_build_path_in_binary'):
                ensure_no_personal_paths(path)

    def test_source_archive_includes_uncommitted_sources_and_excludes_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('// current uncommitted source\n', encoding="utf-8")
            (root / 'src/.env').write_text('synthetic secret', encoding="utf-8")
            (root / '.gitignore').write_text('.env\n', encoding="utf-8")
            (root / 'dist').mkdir()
            (root / 'dist/binary').write_bytes(b'build artifact')
            output = root / 'source.tar.gz'
            source_archive(root, output)
            with tarfile.open(output) as archive:
                self.assertIn('sanctum/src/lib.rs', archive.getnames())
                self.assertFalse(any('.env' in name or '/dist/' in name or '/.git/' in name for name in archive.getnames()))
                self.assertEqual(archive.extractfile('sanctum/src/lib.rs').read(), (root / 'src/lib.rs').read_bytes())

    def test_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'src').mkdir()
            linked = root / 'src/linked'
            if WINDOWS:
                outside = tempfile.TemporaryDirectory()
                self.addCleanup(outside.cleanup)
                external = Path(outside.name)
                (external / 'fixture.txt').write_text('public synthetic fixture\n', encoding='utf-8')
                subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(linked), str(external)],
                               check=True, stdout=subprocess.DEVNULL)
            else:
                linked.symlink_to('/etc/passwd')
            self.assertTrue(reparse(linked))
            with self.assertRaisesRegex(Invalid, 'source_symlink_rejected'):
                source_archive(root, root / 'source.tar.gz')
            if not WINDOWS:
                # Git still lists a tracked leaf when its parent is replaced
                # with a directory link; checking only the leaf misses this.
                linked.unlink()
                linked.mkdir()
                tracked = linked / 'fixture.txt'
                tracked.write_text('public synthetic fixture\n', encoding='utf-8')
                subprocess.run(['git', 'add', '--', 'src/linked/fixture.txt'], cwd=root, check=True)
                tracked.unlink()
                linked.rmdir()
                outside = tempfile.TemporaryDirectory()
                self.addCleanup(outside.cleanup)
                external = Path(outside.name)
                (external / 'fixture.txt').write_text('public synthetic fixture\n', encoding='utf-8')
                linked.symlink_to(external, target_is_directory=True)
                (root / '.gitignore').write_text('src/linked\n', encoding='utf-8')
                self.assertTrue(reparse(linked))
                self.assertFalse(reparse(linked / 'fixture.txt'))
                with self.assertRaisesRegex(Invalid, 'source_symlink_rejected'):
                    source_archive(root, root / 'source.tar.gz')


if __name__ == '__main__':
    unittest.main()
