import tempfile
import unittest
from pathlib import Path
from blackbox_core.scanner import scan_repo

class BlackboxTests(unittest.TestCase):
    def test_scan_reports_language_findings_and_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'main.py').write_text('''import os\n# TODO: fix me\ndef run(x):\n    if x:\n        return x\n    return 0\n''', encoding='utf-8')
            (root / 'README.md').write_text('# demo', encoding='utf-8')
            report = scan_repo(root)
            self.assertEqual(report['project'], root.name)
            self.assertGreaterEqual(report['summary']['files'], 2)
            self.assertGreater(report['summary']['loc'], 0)
            self.assertTrue(any(f.get('type') == 'todo' for f in report['findings']))
            self.assertTrue(any(item.get('name') == 'Python' for item in report['languages']))

    def test_ignored_directory_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'ok.py').write_text('print(1)\n', encoding='utf-8')
            ignored = root / 'node_modules'; ignored.mkdir()
            (ignored / 'secret.py').write_text('password = "verysecretvalue"\n', encoding='utf-8')
            report = scan_repo(root)
            paths = {f['path'] for f in report['files']}
            self.assertIn('ok.py', paths)
            self.assertNotIn('node_modules/secret.py', paths)

if __name__ == '__main__':
    unittest.main()
