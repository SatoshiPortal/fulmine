import json
import contextlib
import copy
import io
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
import run as harness


class OfflineRenewalTests(unittest.TestCase):
    def test_invalid_count_or_outage_combination_starts_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/"artifacts"
            for args in (("0",), ("11",), ("not-a-count",), ("10", "--live-backup-outage")):
                with self.subTest(args=args), patch("live.acceptance") as accept, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        harness.main(["live", "--output", str(output), "--live-refresh-count", *args])
                    self.assertEqual(raised.exception.code, 2)
                    accept.assert_not_called()
                    self.assertFalse(output.exists())

    def test_default_one_preserved_and_requested_ten_never_passes_one(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            with patch("live.acceptance", return_value=None) as accept:
                self.assertEqual(harness.main(["live", "--output", temp]), 0)
                self.assertEqual(accept.call_args.args[-1], 1)
            for returned, status in (("completed 1 of 10; round 2 rejected", 2), (None, 1), ({"completed_refresh_count": 10}, 1)):
                with self.subTest(returned=returned), patch("live.acceptance", return_value=returned) as accept:
                    self.assertEqual(harness.main(["live", "--output", temp, "--live-refresh-count", "10"]), status)
                    accept.assert_called_once()
                    self.assertEqual(accept.call_args.args[-1], 10)

    def test_probe_count_and_candidate_evidence_cannot_be_replayed_as_ten(self):
        evidence = {"status": "blocked", "requested_refresh_count": 10, "completed_refresh_count": 1,
                    "blocked_round": 2, "blocked_reason": "replacement lacks delegate authorization",
                    "commitment_txid": "a"*64, "replacement_outpoint": "b"*64+":0",
                    "checks": {key: True for key in live.OFFLINE_RENEWAL_CHECKS},
                    "rejections": {key: "rejected" for key in live.OFFLINE_RENEWAL_REJECTIONS}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"offline-renewal-evidence.json"
            path.write_text(json.dumps(evidence))
            self.assertEqual(live.offline_renewal_evidence(path, 10, {"commitment_txid": "a"*64}), evidence)
            for category in ("checks", "rejections"):
                for key in evidence[category]:
                    with self.subTest(missing=key):
                        changed = copy.deepcopy(evidence)
                        del changed[category][key]
                        path.write_text(json.dumps(changed))
                        with self.assertRaises(RuntimeError):
                            live.offline_renewal_evidence(path, 10, {"commitment_txid": "a"*64})
            mutations = [("requested_refresh_count", 1), ("completed_refresh_count", 10),
                         ("completed_refresh_count", True), ("blocked_round", 11), ("status", "passed"),
                         ("commitment_txid", "c"*64), ("replacement_outpoint", None), ("blocked_reason", ""),
                         ("checks", {}), ("checks", {"wallet_offline": False}), ("rejections", {})]
            for key, value in mutations:
                with self.subTest(key=key, value=value):
                    changed = copy.deepcopy(evidence)
                    changed[key] = value
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(RuntimeError):
                        live.offline_renewal_evidence(path, 10, {"commitment_txid": "a"*64})


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
    def test_backup_proxy_is_owned_loopback_and_overwrites_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            stack = live.Stack.__new__(live.Stack)
            stack.run = Mock(id="owned", directory=Path(temp))
            stack.config = {"services": {}}
            stack.path = Path(temp)/"compose.json"
            stack.compose = Mock()
            stack.backup_proxy(12345, 12346)
            service = json.loads(stack.path.read_text())["services"]["backup-proxy"]
            config = (Path(temp)/"backup-nginx.conf").read_text()
            self.assertEqual(service["labels"]["bull.recovery.run"], "owned")
            self.assertEqual(service["image"], live.NGINX_IMAGE)
            self.assertIn("listen 127.0.0.1:12345;", config)
            self.assertIn("proxy_pass http://127.0.0.1:12346;", config)
            self.assertIn("proxy_set_header X-Real-IP $remote_addr;", config)
            self.assertNotIn("$http_x_real_ip", config)

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
