import unittest
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch
import remote
from remote import execute_command, verify_tests


class RemoteEvidenceTests(unittest.TestCase):
    def test_repeated_execution(self):
        self.assertEqual(verify_tests("--- PASS: TestA (0.1s)\n" * 3, {"TestA"}, 3), {"TestA": 3})

    def test_false_green_outputs_are_rejected(self):
        for output in ("PASS\n", "--- SKIP: TestA (0.1s)\nPASS\n", "--- PASS: TestAB (0.1s)\n", "    --- PASS: TestA (0.1s)\n", "--- PASS: TestA (0.1s)\n--- FAIL: TestB (0.1s)\n", "--- PASS: TestA (0.1s)\n" * 2):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                verify_tests(output, {"TestA"}, 1)


class BoundedCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "command.log"

    def execute(self, source, **kwargs):
        return execute_command(self.log, [sys.executable, "-c", source], **kwargs)

    def test_success_preserves_combined_output_and_permissions(self):
        self.assertEqual(self.execute("import os; os.write(1,b'out'); os.write(2,b'err')"), "outerr")
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_failure_retains_evidence(self):
        with self.assertRaisesRegex(RuntimeError, "exited 7"):
            self.execute("print('failure evidence'); raise SystemExit(7)")
        self.assertEqual(self.log.read_text(), "failure evidence\n")

    def test_output_limit_stops_an_unbounded_writer(self):
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "exceeded log limit"):
            self.execute("import os\nwhile True: os.write(1,b'x'*4096)", max_bytes=10000, timeout=3)
        self.assertEqual(self.log.stat().st_size, 10000)
        self.assertLess(time.monotonic() - started, 3)

    def test_silent_process_times_out(self):
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.execute("import time; time.sleep(30)", timeout=0.15)
        self.assertLess(time.monotonic() - started, 2)

    def test_closed_stdout_does_not_bypass_timeout(self):
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.execute("import os,time; os.close(1); os.close(2); time.sleep(30)", timeout=0.15)

    def test_timeout_kills_descendants_retaining_stdout(self):
        pidfile = Path(self.directory.name) / "child.pid"
        source = ("import subprocess,sys\n"
                  f"child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
                  f"open({str(pidfile)!r},'w').write(str(child.pid))\n")
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.execute(source, timeout=0.3)
        pid = int(pidfile.read_text())
        # A killed orphan can briefly remain a zombie until PID 1 reaps it.
        state = Path(f"/proc/{pid}/stat")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                if state.read_text().split()[2] == "Z":
                    return
            except (FileNotFoundError, ProcessLookupError):
                return
            time.sleep(0.01)
        self.fail("child is still running")

    def test_existing_log_is_not_overwritten(self):
        self.log.write_text("original")
        with self.assertRaises(FileExistsError):
            self.execute("print('new')")
        self.assertEqual(self.log.read_text(), "original")


class FailureReportTests(unittest.TestCase):
    def run_harness(self, failed_stage=None, cleanup_fails=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        binaries = root / "bin"
        binaries.mkdir()
        for name in ("recovery-tests", "application-tests", "arkade-recovery-prototype"):
            (binaries / name).write_bytes(b"fixture")
        stages = []

        def execute(path, argv, timeout):
            stage = path.stem
            stages.append(stage)
            if stage == failed_stage or (stage == "cleanup" and cleanup_fails):
                raise RuntimeError(stage + " deliberate failure")
            if stage.startswith("hash-"):
                return hashlib.sha256(b"fixture").hexdigest() + " binary"
            names = remote.REQUIRED if stage == "recovery" else remote.GATES if stage == "gates" else ()
            return "".join(f"--- PASS: {name} (0.1s)\n" for name in names)

        argv = ["remote.py", "--ssh-config", str(root / "ssh"), "--host", "test-vm", "--binaries", str(binaries),
                "--output", str(root / "output"), "--repeat", "1"]
        with patch.object(sys, "argv", argv), patch.object(remote, "execute_command", execute), contextlib.redirect_stdout(io.StringIO()):
            code = remote.main()
        reports = list((root / "output").glob("*/report.json"))
        self.assertEqual(len(reports), 1)
        return code, json.loads(reports[0].read_text()), stages

    def test_success_contains_all_required_evidence(self):
        code, report, stages = self.run_harness()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(set(report["tests"]), remote.REQUIRED | remote.GATES)
        self.assertEqual(stages[-1], "cleanup")

    def test_test_failure_is_preserved_and_cleanup_runs(self):
        code, report, stages = self.run_harness("recovery")
        self.assertEqual(code, 1)
        self.assertEqual(report["error"], "recovery deliberate failure")
        self.assertNotIn("gates", stages)
        self.assertEqual(stages[-1], "cleanup")

    def test_cleanup_failure_revokes_success(self):
        code, report, _ = self.run_harness(cleanup_fails=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "failed")
        self.assertIn("cleanup_error", report)

    def test_primary_and_cleanup_failures_are_both_retained(self):
        code, report, _ = self.run_harness("setup", cleanup_fails=True)
        self.assertEqual(code, 1)
        self.assertIn("setup", report["error"])
        self.assertIn("cleanup", report["cleanup_error"])
