import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import backend_ci


class BackendReleaseEvidenceTests(unittest.TestCase):
    def test_rust_required_tests_cannot_be_filtered_or_ignored(self):
        for missing in backend_ci.RUST_REQUIRED:
            lines = [f"test {name} ... {'ignored' if name == missing else 'ok'}"
                     for name in backend_ci.RUST_REQUIRED]
            with self.assertRaises(RuntimeError):
                backend_ci.verify_rust("\n".join(lines))
        with self.assertRaises(RuntimeError):
            backend_ci.verify_rust("test result: ok. 0 passed; 0 failed; 2 filtered out")
        self.assertEqual(backend_ci.verify_rust("\n".join(
            f"test {name} ... ok" for name in backend_ci.RUST_REQUIRED)), sorted(backend_ci.RUST_REQUIRED))

    def test_every_required_go_case_must_execute(self):
        for missing in backend_ci.GO_REQUIRED:
            lines = [f"--- {'SKIP' if name == missing else 'PASS'}: {name} (0.00s)"
                     for name in backend_ci.GO_REQUIRED]
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                backend_ci.verify_tests("\n".join(lines), backend_ci.GO_REQUIRED, 1)

    def test_missing_or_different_companion_fixture_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "fulmine/test/recovery/fixtures/recovery-wire-v1.json"
            canonical.parent.mkdir(parents=True)
            canonical.write_bytes(b"golden fixture")
            with self.assertRaises(FileNotFoundError):
                backend_ci.check_fixtures(root / "fulmine", root / "backup")
            companion = root / "backup/tests/fixtures/recovery-wire-v1.json"
            companion.parent.mkdir(parents=True)
            companion.write_bytes(b"changed fixture")
            with self.assertRaises(RuntimeError):
                backend_ci.check_fixtures(root / "fulmine", root / "backup")
            companion.write_bytes(canonical.read_bytes())
            self.assertEqual(len(backend_ci.check_fixtures(root / "fulmine", root / "backup")), 64)

    def test_component_run_removes_live_settings_and_records_both_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fulmine, backup, output = root / "fulmine", root / "backup", root / "evidence"
            for target in (fulmine / "test/recovery/fixtures/recovery-wire-v1.json",
                           backup / "tests/fixtures/recovery-wire-v1.json"):
                target.parent.mkdir(parents=True)
                target.write_bytes(b"fixture")
            for name in ("backup-server", "arkade-recovery-prototype"):
                binary = backup / "target/debug" / name
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(name.encode())
            commands = []

            def execute(path, argv, **kwargs):
                commands.append(argv)
                if path.stem == "rust-tests":
                    return "\n".join(f"test {name} ... ok" for name in backend_ci.RUST_REQUIRED)
                if path.stem == "go-tests":
                    return "\n".join(f"--- PASS: {name} (0.00s)" for name in backend_ci.GO_REQUIRED)
                return ""

            arguments = ["backend_ci.py", "--backup-root", str(backup), "--output", str(output)]
            with patch("sys.argv", arguments), patch.object(backend_ci, "execute_command", execute), \
                    patch.object(backend_ci, "__file__", str(fulmine / "test/recovery/backend_ci.py")), \
                    patch.dict(os.environ, {"RECOVERY_LIVE_CONFIG": "must-not-use", "CARGO_TARGET_DIR": "elsewhere"}):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(backend_ci.main(), 0)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "passed")
            self.assertEqual(set(report["binary_sha256"]), {"backup-server", "arkade-recovery-prototype"})
            for command in commands:
                self.assertIn("--unset=RECOVERY_LIVE_CONFIG", command)
                self.assertIn("--unset=CARGO_TARGET_DIR", command)
            build = next(command for command in commands if "build" in command)
            self.assertIn("backup-server", build)
            self.assertIn("arkade-recovery-prototype", build)

    def test_failed_preflight_writes_failed_report_without_running_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            arguments = ["backend_ci.py", "--backup-root", directory, "--output", str(output)]
            with patch("sys.argv", arguments), patch.object(backend_ci, "execute_command") as command:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(backend_ci.main(), 1)
                command.assert_not_called()
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
