"""Domain subset boundaries, provenance and all-or-rollback publication."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rules_generator', Path(__file__).resolve().parents[1] / 'scripts/update-bundled-rules.py')
rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rules)


class BundledRules(unittest.TestCase):
    def test_conditional_rules_are_never_widened(self):
        blocked, allowed = rules.extract('||ads.example^\n||AD.example^\n||tracker.example^$third-party\n||cdn.example^$script\n||path.example/foo\n/ads/\n@@||allowed.example^\n||evil.example.com/path^\n')
        self.assertEqual(blocked, {'ads.example', 'ad.example'})
        self.assertEqual(allowed, {'allowed.example'})

    def test_literal_exceptions_remove_ancestor_and_descendant_blocks(self):
        exceptions = rules.exception_hosts('@@||cdn.example.com/path$script\n@@https://safe.example/login\n@@||*.allowed.example^$image\n@@/generic-regex/\n')
        self.assertEqual(exceptions, {'cdn.example.com', 'safe.example', 'allowed.example'})
        self.assertEqual(rules.reduce_domains({'example.com','cdn.example.com','sub.cdn.example.com','ads.example.com','unrelated.example','safe.example','allowed.example','ads.allowed.example'}, exceptions), ['ads.example.com','unrelated.example'])

    def test_domain_label_boundaries_and_redundant_children(self):
        self.assertEqual(rules.reduce_domains({'ad.example','sub.ad.example','badad.example','example.net'}, set()), ['ad.example','badad.example','example.net'])
        for bad in ['*.example.com','bad..example','-bad.example','bad-.example','ümlaut.example','İ.com','ſ.com','a.' + 'b'*64, 'localhost']:
            self.assertIsNone(rules.DOMAIN.fullmatch(bad),bad)
        self.assertEqual(rules.extract('||İ.com^\n||ſ.com^'),(set(),set()))

    def test_committed_data_reproduces_with_all_source_hashes(self):
        lock = json.loads(rules.LOCK.read_text(encoding='utf8'))
        inputs = {item['file']: (rules.ROOT/'rules/vendor'/item['file']).read_bytes() for item in lock['sources']}
        files = rules.generate(lock, inputs)
        for path, data in files.items():
            self.assertEqual(path.read_bytes(), data, str(path))
        tampered = dict(inputs); name = next(iter(tampered)); tampered[name] += b'\n||tampered.example^\n'
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            rules.generate(lock, tampered)

    def test_partial_publication_failure_restores_every_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory)/'first', Path(directory)/'second'
            first.write_bytes(b'previous')
            original = rules.os.replace
            def replace(source, target):
                if target == second:
                    raise OSError('simulated apply failure')
                return original(source, target)
            with patch.object(rules.os, 'replace', replace):
                with self.assertRaises(OSError):
                    rules.publish({first:b'new', second:b'created'})
            self.assertEqual(first.read_bytes(),b'previous')
            self.assertFalse(second.exists())
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()),['first'])

    def test_failed_rollback_preserves_previous_bytes_in_recovery_file(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory)/'first', Path(directory)/'second'
            first.write_bytes(b'previous-first'); second.write_bytes(b'previous-second')
            original = rules.os.replace
            def replace(source, target):
                if target == second or Path(source).name.startswith('.nullad-rule-old-'):
                    raise OSError('simulated publication/rollback failure')
                return original(source, target)
            with patch.object(rules.os, 'replace', replace):
                with self.assertRaisesRegex(RuntimeError, 'Rollback incomplete; keep recovery copies'):
                    rules.publish({first:b'new', second:b'new-second'})
            backups = list(Path(directory).glob('.nullad-rule-old-*'))
            self.assertEqual(len(backups),1); self.assertEqual(backups[0].read_bytes(),b'previous-first')
            self.assertEqual(first.read_bytes(),b'new');self.assertEqual(second.read_bytes(),b'previous-second')


if __name__ == '__main__':
    unittest.main()
