# SPDX-License-Identifier: Apache-2.0
"""Pure input and opt in guards. This suite never invokes the JDK or Android."""

import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "owner/tests/native-accounts-host/run.py"


class NativeAccountsHostRunnerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("native_accounts_host_runner", RUNNER)
        cls.runner = importlib.util.module_from_spec(spec)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("implicit JVM")):
            spec.loader.exec_module(cls.runner)

    def test_no_default_invocation(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.runner.parse_args([])
        with mock.patch("subprocess.Popen", side_effect=AssertionError("implicit JVM")):
            self.assertEqual(len(self.runner.source_inputs()), 24)

    def test_only_declared_current_production_sources(self):
        runner = self.runner
        self.assertEqual(len(runner.FACADES), 20)
        self.assertEqual(len(runner.TESTS), 2)
        self.assertEqual([str(p.relative_to(ROOT)) for p in runner.source_inputs()[20:22]],
                         list(runner.PRODUCTION))
        self.assertFalse(any("source" in p.relative_to(ROOT).parts for p in runner.source_inputs()))

    def test_fresh_owned_output_guard(self):
        runner = self.runner
        with self.assertRaisesRegex(ValueError, "fresh absolute directory"):
            runner.owned_output(ROOT / "owner" / "tests")
        with self.assertRaisesRegex(ValueError, "output parent must be canonical"):
            runner.owned_output(Path("relative-output"))

    def test_public_runner_has_no_session_specific_admission(self):
        source = RUNNER.read_text()
        for policy in ("GUEST-STATUS", "status-exact", "root-fsid", "hdd-fsid",
                       "root-device", "hdd-device", "statvfs", "96 * 2**20"):
            self.assertNotIn(policy, source)
        self.assertIn("os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC", source)
        self.assertNotIn("stdin=subprocess.DEVNULL", source)
        self.assertIn("start_new_session=False", source)
        self.assertNotIn("start_new_session=True", source)
        self.assertIn("os.getpid() == os.getpgrp()", source)
        self.assertNotIn("os.killpg", source)


if __name__ == "__main__":
    unittest.main()
