# SPDX-License-Identifier: Apache-2.0
"""Real host fixture builds/failure recovery, not Android compiler qualification."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class OwnerProjectTests(unittest.TestCase):
    def test_incremental_make_dependencies_failure_and_recursive_jobs(self):
        self.assertIsNotNone(shutil.which('make'))
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)/'incremental project'
            shutil.copytree(ROOT/'tests/owner-project', project)
            def run(*args):
                return subprocess.run(['make', '--no-print-directory', *args], cwd=project,
                                      capture_output=True, text=True, timeout=90)
            def stamps():
                return {name:(project/'build'/name).stat().st_mtime_ns
                        for name in ['main.o','parse.o','summary.o','stats']}
            p = run()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            original = stamps()
            for name in ['main.d','parse.d','summary.d']:
                self.assertIn('include/stats.h', (project/'build'/name).read_text())
            p = run()
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(stamps(), original)
            self.assertEqual(run('-q').returncode, 0)
            header = project/'include/stats.h'
            header.write_text(header.read_text().replace('"v1"','"v2"'))
            self.assertEqual(run('-q').returncode, 1)
            p = run('--trace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            rebuilt = stamps()
            self.assertTrue(all(rebuilt[name] > original[name] for name in original))
            source = project/'src/summary.cpp'
            source.write_text(source.read_text()+'\n// one-unit rebuild\n')
            p = run('--trace')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            one_unit = stamps()
            self.assertEqual(one_unit['main.o'], rebuilt['main.o'])
            self.assertEqual(one_unit['parse.o'], rebuilt['parse.o'])
            self.assertGreater(one_unit['summary.o'], rebuilt['summary.o'])
            binary = project/'build/stats'
            good = hashlib.sha256(binary.read_bytes()).hexdigest()
            saved = source.read_bytes(); source.write_text('#error deliberate\n')
            self.assertNotEqual(run().returncode, 0)
            self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), good)
            self.assertEqual(list((project/'build').glob('*.tmp.*')), [])
            source.write_bytes(saved)
            self.assertEqual(run().returncode, 0)
            p = run('-j2', 'jobserver-check')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('JOB_ALPHA', p.stdout); self.assertIn('JOB_BETA', p.stdout)
            self.assertNotIn('jobserver unavailable', p.stderr)
            self.assertEqual(run('path-fallback').returncode, 0)
            moved = Path(temporary)/'moved project'; project.rename(moved); project = moved
            self.assertEqual(run('-q').returncode, 0)
            p = run('check')
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('v2 count=3 mean=4 rms=4.32049', p.stdout)

    def test_serial_project_rebuild_edit_relocate_and_failed_build(self):
        for tool in ['c++', 'ar', 'ranlib', 'sh', 'mktemp']:
            self.assertIsNotNone(shutil.which(tool), tool)
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)/'project with spaces'
            shutil.copytree(ROOT/'tests/owner-project', project)

            def build():
                return subprocess.run(['sh', 'build.sh'], cwd=project, capture_output=True,
                                      text=True, timeout=90)

            p = build()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('BUILD_OK v1 count=3 mean=4 rms=4.32049', p.stdout)
            binary = project/'build/stats'
            for args in [[], ['nan'], ['1x'], ['1e999'], ['1e200']]:
                p = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=5)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertTrue(p.stderr.startswith('error:'))
            header = project/'include/stats.h'
            header.write_text(header.read_text().replace('"v1"', '"v2"'))
            p = build()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('BUILD_OK v2 count=3 mean=4 rms=4.32049', p.stdout)
            working_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
            source = project/'src/summary.cpp'
            saved = source.read_bytes()
            source.write_text('#error deliberate failing build\n')
            p = build()
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn('BUILD_OK', p.stdout)
            self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), working_hash)
            self.assertEqual(list((project/'build').glob('.work.*')), [])
            source.write_bytes(saved)
            p = build()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            moved = Path(temporary)/'relocated'
            project.rename(moved)
            p = subprocess.run([str(moved/'build/stats'), '3', '4'], capture_output=True,
                               text=True, timeout=5)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, 'v2 count=2 mean=3.5 rms=3.53553\n')
