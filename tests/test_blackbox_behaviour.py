import shutil, subprocess, tempfile, unittest
from pathlib import Path

from blackbox_core.scanner import scan_repo


class ScannerBehaviourTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.root = Path(self._tmp.name) / 'repo'; self.root.mkdir()
    def tearDown(self):
        self._tmp.cleanup()

    def put(self, rel, text):
        p = self.root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding='utf-8'); return p

    def test_secrets_are_located_but_never_echoed(self):
        self.put('config.py', 'x = 1\nAWS = "AKIAABCDEFGHIJKLMNOP"\npassword = "hunter2hunter2"\n')
        findings = [f for f in scan_repo(self.root)['findings'] if f['type'] == 'secret']
        self.assertEqual({(f['title'], f['line']) for f in findings}, {('AWS access key', 2), ('Possible secret assignment', 3)})
        self.assertFalse(any('AKIA' in f['detail'] or 'hunter2' in f['detail'] for f in findings))

    def test_private_key_is_critical_and_sorted_first(self):
        self.put('notes.md', 'TODO later\n'); self.put('id_rsa.txt', '-----BEGIN RSA PRIVATE KEY-----\nabc\n')
        self.assertEqual(scan_repo(self.root)['findings'][0]['severity'], 'critical')

    def test_js_import_cycle_is_reported(self):
        self.put('src/a.js', "import b from './b'\n"); self.put('src/b.js', "const a = require('./a')\n"); self.put('src/c.js', "import React from 'react'\n")
        report = scan_repo(self.root)
        self.assertEqual([sorted(c) for c in report['cycles']], [['src/a.js', 'src/b.js']])
        self.assertIn({'name': 'react', 'count': 1}, report['external_imports'])

    def test_python_relative_and_package_imports_resolve_locally(self):
        self.put('pkg/__init__.py', ''); self.put('pkg/util.py', 'def f():\n    return 1\n')
        self.put('pkg/main.py', 'from .util import f\nimport pkg\nimport requests\n')
        report = scan_repo(self.root)
        main = next(f for f in report['files'] if f['path'] == 'pkg/main.py')
        self.assertEqual(set(main['imports_local']), {'pkg/util.py', 'pkg/__init__.py'})
        self.assertIn('requests', [e['name'] for e in report['external_imports']])

    def test_binary_files_are_not_parsed_as_text(self):
        (self.root / 'blob.py').write_bytes(b'\x00\x01 TODO password = "abcdefghij"')
        report = scan_repo(self.root)
        self.assertEqual(report['findings'], []); self.assertEqual(report['summary']['loc'], 0)

    def test_frameworks_are_detected_from_markers_and_manifests(self):
        self.put('package.json', '{"dependencies": {"react": "^19"}}'); self.put('Cargo.toml', '[package]\nname = "x"\n')
        self.assertTrue({'React', 'Rust/Cargo'} <= set(scan_repo(self.root)['frameworks']))

    def test_repository_inside_a_folder_named_like_an_ignored_one_is_still_scanned(self):
        nested = Path(self._tmp.name) / 'build' / 'app'; nested.mkdir(parents=True)
        (nested / 'main.py').write_text('print(1)\n'); (nested / 'dist').mkdir(); (nested / 'dist' / 'bundle.js').write_text('x')
        paths = {f['path'] for f in scan_repo(nested)['files']}
        self.assertEqual(paths, {'main.py'})

    @unittest.skipUnless(shutil.which('git'), 'needs git')
    def test_git_repositories_scan_tracked_files_only(self):
        self.put('tracked.py', 'print(1)\n'); self.put('scratch.py', 'print(2)\n')
        git = ['git', '-C', str(self.root), '-c', 'user.email=t@t', '-c', 'user.name=t']
        subprocess.run(git[:3] + ['init', '-q'], check=True)
        subprocess.run(git + ['add', 'tracked.py'], check=True); subprocess.run(git + ['commit', '-qm', 'init'], check=True)
        self.assertEqual({f['path'] for f in scan_repo(self.root)['files']}, {'tracked.py'})

    def test_missing_directory_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_repo(self.root / 'nope')


if __name__ == '__main__':
    unittest.main()
