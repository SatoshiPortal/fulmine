import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import coverage
import live
import paths


class LiveEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = sqlite3.connect(self.root / "fulmine.db")
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE delegate_task(id TEXT, status INT, commitment_txid TEXT)")
        self.db.execute("INSERT INTO delegate_task VALUES('task', 1, ?)", ("a"*64,))
        self.db.commit()
        self.log = self.root / "fulmine.log"
        self.ack = f"recovery backup acknowledged commitment={'a'*64} task=task ciphertext={'b'*64}\n"
        self.submit = f"recovery forfeits submission starting commitment={'a'*64}\n"

    def test_candidate_bound_completion(self):
        self.log.write_text(self.ack+self.submit)
        result = live.completed_refresh(self.root, self.log)
        self.assertEqual(result["commitment_txid"], "a"*64)
        self.assertLess(result["backup_ack_sequence"], result["forfeit_submit_sequence"])

    def test_pending_candidate_is_not_completed(self):
        self.db.execute("UPDATE delegate_task SET status=0")
        self.db.commit()
        self.assertIsNone(live.completed_refresh(self.root, self.log))

    def test_wrong_candidate_missing_ack_and_late_ack_rejected(self):
        for lines in (self.submit, self.submit+self.ack, self.ack.replace("a"*64, "c"*64)+self.submit):
            with self.subTest(lines=lines):
                self.log.write_text(lines)
                with self.assertRaises(RuntimeError):
                    live.completed_refresh(self.root, self.log)

    def test_failed_task_is_not_success(self):
        self.db.execute("UPDATE delegate_task SET status=2")
        self.db.commit()
        with self.assertRaises(RuntimeError):
            live.completed_refresh(self.root, self.log)

    def test_outage_requires_retained_candidate_and_no_forfeits(self):
        self.db.execute("UPDATE delegate_task SET status=2, commitment_txid=NULL")
        self.db.commit()
        self.log.write_text("")
        with self.assertRaisesRegex(RuntimeError, "candidate publication"):
            live.failed_refresh(self.root, self.log)
        outbox = self.root/"recovery-prototype"
        outbox.mkdir()
        (outbox/"outbox-test.json").write_text("{}")
        self.assertTrue(live.failed_refresh(self.root, self.log))
        self.log.write_text(self.submit)
        with self.assertRaisesRegex(RuntimeError, "publication gate"):
            live.failed_refresh(self.root, self.log)


class CleanupTests(unittest.TestCase):
    def test_failed_logs_do_not_suppress_owned_compose_down(self):
        stack = live.Stack.__new__(live.Stack)
        stack.processes = []
        stack.run = Mock(id="owned")
        stack.run.command.return_value = "owned\n"
        def compose(*args, **kwargs):
            if args[0] == "logs":
                raise RuntimeError("failed logs")
            return "container\n" if args[0] == "ps" else ""
        stack.compose = Mock(side_effect=compose)
        with self.assertRaisesRegex(RuntimeError, "log collection"):
            stack.close()
        self.assertIn("down", [call.args[0] for call in stack.compose.call_args_list])

    def test_unowned_container_prevents_deletion(self):
        stack = live.Stack.__new__(live.Stack)
        stack.processes = []
        stack.run = Mock(id="owned")
        stack.run.command.return_value = "somebody-else\n"
        stack.compose = Mock(return_value="container\n")
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            stack.close()
        self.assertNotIn("down", [call.args[0] for call in stack.compose.call_args_list])


class CoverageTests(unittest.TestCase):
    def test_later_pass_cannot_hide_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            name = json.loads((Path(coverage.__file__).parent / "edge-cases.json").read_text())[0]["tests"][0]
            (root/"test.log").write_text(f"--- FAIL: {name} (0.01s)\n--- PASS: {name} (0.01s)\n")
            result = coverage.report(root)
            self.assertEqual(result["cases"][0]["status"], "failed")


class ProvenanceTests(unittest.TestCase):
    def test_modified_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in live.BINARIES:
                (root/name).write_bytes(name.encode())
            manifest = live.binary_manifest(root)
            self.assertIsNone(manifest["sources"])
            manifest["sources"] = {"fulmine": "a"*40, "backup": "b"*40}
            self.assertEqual(live.binary_manifest(root, manifest), manifest)
            (root/"fulmine").write_bytes(b"different build")
            with self.assertRaisesRegex(RuntimeError, "differs from build manifest"):
                live.binary_manifest(root, manifest)

    def test_partial_revision_cannot_be_used_as_build_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in live.BINARIES:
                (root/name).write_bytes(name.encode())
            manifest = live.binary_manifest(root)
            manifest["sources"] = {"fulmine": "abc1234", "backup": "b"*40}
            with self.assertRaisesRegex(RuntimeError, "full Fulmine and backup Git revisions"):
                live.binary_manifest(root, manifest)

    def test_detached_runner_honors_checkout_overrides(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = os.environ.copy()
            env.update(RECOVERY_FULMINE_ROOT=str(root/"wallet-service"), RECOVERY_BACKUP_ROOT=str(root/"metadata-service"))
            result = subprocess.run([sys.executable, "-c", "import json,paths; print(json.dumps([str(paths.FULMINE),str(paths.BACKUP)]))"], cwd=paths.HARNESS, env=env, text=True, capture_output=True, check=True)
            self.assertEqual(json.loads(result.stdout), [str(root/"wallet-service"), str(root/"metadata-service")])


if __name__ == "__main__":
    unittest.main()
