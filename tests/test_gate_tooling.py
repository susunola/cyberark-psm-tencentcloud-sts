"""Negative controls for the gate scripts, which are what makes every other check real.

A check that quietly stops detecting a problem leaves the gate looking green, which is worse
than having no check at all: the failure mode is invisible. Each script here is therefore fed
a deliberately broken input and required to refuse it, and a good input and required to accept
it, so a refusal that has become unconditional is caught too.
"""

import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import check_docs, check_guard_mutations, pin_lock_hashes

ROOT = Path(__file__).resolve().parents[1]


class DocumentationCheckTests(unittest.TestCase):
    """check_docs.py must refuse each class of broken documentation."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        # Resolved, because the check resolves every link before comparing it to its root.
        self.base = Path(self.folder.name).resolve()
        self.root = self.base / 'checkout'
        (self.root / 'docs').mkdir(parents=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def run_check(self):
        """Run the check against the temporary root and return everything it printed."""
        output = io.StringIO()
        with patch.object(check_docs, 'ROOT', self.root), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            check_docs.check()
        return output.getvalue()

    def refusal(self):
        """Run the check and return the message it refuses with."""
        with self.assertRaises(ValueError) as caught:
            self.run_check()
        return str(caught.exception)

    def test_accepts_a_valid_link_anchor_and_cli_example(self):
        self.write('docs/manual.md', '# Manual\n\n## Install\n\nRun it.\n')
        self.write('docs/INSTALLATION-AND-USAGE.md', 'See [the manual](manual.md#install).\n\npython scripts/pamctl.py capabilities | probe\n')
        self.assertIn('1 local links and 1 CLI examples', self.run_check())

    def test_refuses_a_link_to_a_missing_file(self):
        self.write('README.md', 'See [the manual](docs/gone.md).\n')
        self.assertEqual(self.refusal(), 'Broken local documentation link: README.md')

    def test_refuses_a_link_that_escapes_the_documentation_root(self):
        # The file exists, so only the containment check can refuse this one.
        (self.base / 'outside.md').write_text('# Outside\n', encoding='utf-8')
        self.write('README.md', 'See [the manual](../outside.md).\n')
        self.assertEqual(self.refusal(), 'Broken local documentation link: README.md')

    def test_refuses_an_anchor_that_no_longer_exists(self):
        self.write('docs/manual.md', '# Manual\n\n## Install\n')
        self.write('README.md', 'See [installing](docs/manual.md#uninstalling).\n')
        self.assertEqual(self.refusal(), 'Broken local documentation anchor: README.md')

    def test_refuses_an_unbalanced_code_fence(self):
        self.write('README.md', '```text\nunclosed\n')
        self.assertEqual(self.refusal(), 'Unbalanced code fence: README.md')

    def test_refuses_a_cli_example_that_the_parser_does_not_accept(self):
        self.write('docs/INSTALLATION-AND-USAGE.md', 'python scripts/pamctl.py not-a-command\n')
        with self.assertRaises(SystemExit) as caught:
            self.run_check()
        self.assertEqual(caught.exception.code, 2)


class DependencyHashCheckTests(unittest.TestCase):
    """pin_lock_hashes.py must keep the two failure severities apart."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)

    def write(self, name, text):
        path = self.base / name
        path.write_text(text, encoding='utf-8')
        return path

    def verify(self, published, recorded):
        """Run verify() against a pinned lock, with the index replaced by a fixed answer."""
        lock = self.write('requirements.lock.txt', 'flask==1.0\n')
        hashes = self.write('requirements.lock.hashes.txt', recorded)
        output = io.StringIO()
        with patch.object(pin_lock_hashes, 'LOCK_FILE', lock), patch.object(pin_lock_hashes, 'published_hashes', lambda name, version: published), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = pin_lock_hashes.verify(hashes)
        return code, output.getvalue()

    def test_reads_pinned_entries_and_refuses_an_unpinned_one(self):
        # This parser takes the version-pinned lock; the generated hash file is read by
        # recorded_hashes() instead, which is why a --hash continuation line is not input here.
        lock = self.write('pinned.txt', '# comment\n\nFlask==3.1.3\nredis==8.1.0\n')
        self.assertEqual(pin_lock_hashes.pinned_requirements(lock), [('Flask', '3.1.3'), ('redis', '8.1.0')])
        inline = self.write('inline.txt', 'flask==1.0 --hash=sha256:aaa\n')
        self.assertEqual(pin_lock_hashes.pinned_requirements(inline), [('flask', '1.0')])
        loose = self.write('loose.txt', 'flask>=3\n')
        with self.assertRaises(ValueError):
            pin_lock_hashes.pinned_requirements(loose)

    def test_reads_the_hashes_a_generated_file_records_per_package(self):
        hashes = self.write('generated.txt', '# header\nflask==1.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\nredis==2.0 \\\n    --hash=sha256:ccc\n')
        self.assertEqual(pin_lock_hashes.recorded_hashes(hashes), {'flask': {'aaa', 'bbb'}, 'redis': {'ccc'}})

    def test_an_exact_match_is_in_sync(self):
        code, output = self.verify(['aaa'], 'flask==1.0 \\\n    --hash=sha256:aaa\n')
        self.assertEqual(code, 0)
        self.assertIn('is in sync with requirements.lock.txt', output)

    def test_a_recorded_hash_that_is_no_longer_published_fails(self):
        code, output = self.verify(['bbb'], 'flask==1.0 \\\n    --hash=sha256:aaa\n')
        self.assertEqual(code, 2)
        self.assertIn('problem: flask==1.0: 1 recorded hash(es) are no longer published', output)

    def test_an_unrecorded_upstream_artifact_is_only_an_advisory(self):
        code, output = self.verify(['aaa', 'bbb'], 'flask==1.0 \\\n    --hash=sha256:aaa\n')
        self.assertEqual(code, 0)
        self.assertIn('advisory: flask==1.0: 1 upstream artifact(s) are not recorded', output)
        self.assertIn('re-run without --check to record the new artifacts', output)

    def test_a_package_with_no_recorded_hashes_fails(self):
        code, output = self.verify(['aaa'], 'redis==2.0 \\\n    --hash=sha256:ccc\n')
        self.assertEqual(code, 2)
        self.assertIn('problem: flask==1.0: no hashes recorded', output)

    def test_a_missing_hash_file_is_refused_before_any_request(self):
        missing = self.base / 'absent.txt'
        with patch.object(sys, 'argv', ['pin_lock_hashes.py', '--check', '--out', str(missing)]), contextlib.redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit) as caught:
            pin_lock_hashes.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('is missing; generate it before deploying', errors.getvalue())


class GuardMutationTableTests(unittest.TestCase):
    """check_guard_mutations.py is the guard on the guards, so it is guarded here."""

    def test_every_pattern_targets_an_existing_file_exactly_once(self):
        table = check_guard_mutations.MUTATIONS
        self.assertGreater(len(table), 10)
        for description, path, old, new in table:
            with self.subTest(guard=description):
                source = (ROOT / path).read_text(encoding='utf-8')
                self.assertEqual(source.count(old), 1, f'{description}: the pattern must match one place in {path}')
                self.assertNotEqual(old, new)

    def test_list_reports_every_guard(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_guard_mutations.py'), '--list'], cwd=ROOT, capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.strip().splitlines()), len(check_guard_mutations.MUTATIONS))

    def test_refuses_to_run_when_a_target_file_differs_from_head(self):
        # A run against uncommitted work could overwrite it, so the script must refuse first.
        targets = sorted({path for _, path, _, _ in check_guard_mutations.MUTATIONS})
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / 'scripts').mkdir()
            shutil.copy2(ROOT / 'scripts/check_guard_mutations.py', repo / 'scripts/check_guard_mutations.py')
            for target in targets:
                destination = repo / target
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / target, destination)
            identity = ['-c', 'user.name=gate test', '-c', 'user.email=gate@example.invalid']
            for command in (['git', 'init', '-q'], ['git', *identity, 'add', '.'], ['git', *identity, 'commit', '-q', '-m', 'copy the guard table with its targets']):
                subprocess.run(command, cwd=repo, capture_output=True, text=True, check=True, timeout=120)
            dirty = repo / targets[0]
            dirty.write_text(dirty.read_text(encoding='utf-8') + '\n', encoding='utf-8')
            result = subprocess.run([sys.executable, str(repo / 'scripts/check_guard_mutations.py')], cwd=repo, capture_output=True, text=True, timeout=300, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('Refusing to run', result.stderr)
        self.assertIn(targets[0], result.stderr)


if __name__ == '__main__':
    unittest.main()
