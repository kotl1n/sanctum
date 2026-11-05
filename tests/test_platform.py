from pathlib import Path
import unittest
from test_installer import WINDOWS
from platform_support import relative_path, windows_launcher


class PlatformTests(unittest.TestCase):
    def test_release_paths_reject_drives_unc_ads_and_traversal(self):
        for value in ('../outside', '/outside', 'C:outside', 'C:/outside', '//host/share',
                      'a/../outside', 'a\\..\\outside', 'a:stream', '\\outside',
                      'a.', 'file ', 'con.txt', 'NUL', 'a/COM1.exe'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                relative_path(value)
        self.assertEqual(relative_path('plugin/bin/sanctum.exe').as_posix(), 'plugin/bin/sanctum.exe')

    def test_launcher_quotes_paths_and_forwards_arguments_without_evaluation(self):
        home = Path("C:/synthetic/Тест'овый")
        profile = {'desktop':{'app.exe':'fixture', 'node.exe':'fixture'},
                   'launch':{'app':'app.exe', 'node':'node.exe'}}
        files = windows_launcher(home, {}, profile, Path('C:/Desktop'), home / 'settings.json')
        self.assertIn("Тест''овый".encode('utf-8'), files[1][1])
        self.assertIn(b'@args', files[1][1])
        self.assertNotIn(b'Invoke-Expression', files[1][1])

    def test_launcher_rejects_unlisted_components(self):
        profile = {'desktop':{'app.exe':'fixture'}, 'launch':{'app':'app.exe', 'node':'unlisted.exe'}}
        with self.assertRaises(ValueError):
            windows_launcher(Path('user'), {}, profile, Path('desktop'), Path('settings'))


if __name__ == '__main__':
    unittest.main()
