"""Tests of orchestration and acceptance assertions; no live-stack claims."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import run


def valid_evidence():
    # Deliberately synthetic evidence, used ONLY to test the validator.
    return {
        "setup": {"chain": "regtest", "isolated": True},
        "prepare_wallet": {"nostr_public_key": "11" * 32, "original_outpoint": "22" * 32 + ":0", "fee_balance_sats": 0, "baseline_backed_up": True},
        "stop_wallet": {"wallet_running": False},
        "refresh_and_backup": {"replacement_outpoint": "33" * 32 + ":0", "commitment_txid": "44" * 32, "ciphertext_sha256": "55" * 32, "commitment_confirmations": 1, "backup_ack_sequence": 1, "forfeit_submit_sequence": 2, "wallet_running": False, "fee_balance_sats": 0},
        "stop_ark_and_delegate": {"ark_running": False, "indexer_running": False, "delegate_running": False, "backup_running": True, "bitcoin_running": True, "recovery_network_restricted": True},
        "erase_wallet": {"wallet_state_removed": True, "retained_recovery_material": ["seed"]},
        "restore_and_fetch": {"nostr_public_key": "11" * 32, "replacement_outpoint": "33" * 32 + ":0", "ciphertext_sha256": "55" * 32, "bitcoin_signatures_verified": True, "owner_authenticated_fetch": True, "fee_balance_sats": 0, "ark_requests": 0, "delegate_requests": 0},
        "fund_exit": {"funding_txid": "66" * 32, "funding_confirmations": 1, "funding_sats": 20000, "fee_payer": "user", "ark_requests": 0, "delegate_requests": 0},
        "exit_and_sweep": {"sweep_txid": "77" * 32, "sweep_confirmations": 1, "received_sats": 98000, "spent_outpoint": "33" * 32 + ":0", "destination_verified_from_seed": True, "fee_payer": "user", "ark_requests": 0, "delegate_requests": 0},
    }


class AcceptanceTests(unittest.TestCase):
    def validate(self, evidence):
        history = {}
        for step in run.STEPS:
            run.validate_step(step, evidence[step], history)
            history[step] = evidence[step]

    def test_valid_contract(self):
        self.validate(valid_evidence())

    def test_missing_any_required_evidence_is_failure(self):
        source = valid_evidence()
        for step, fields in source.items():
            for field in fields:
                with self.subTest(step=step, field=field):
                    evidence = copy.deepcopy(source)
                    del evidence[step][field]
                    with self.assertRaises(run.Failed):
                        self.validate(evidence)

    def test_adversarial_state_transitions(self):
        mutations = [
            ("setup", "chain", "main"),
            ("setup", "isolated", False),
            ("refresh_and_backup", "backup_ack_sequence", 3),
            ("refresh_and_backup", "backup_ack_sequence", True),
            ("refresh_and_backup", "replacement_outpoint", "22" * 32 + ":0"),
            ("refresh_and_backup", "wallet_running", True),
            ("refresh_and_backup", "fee_balance_sats", 1000),
            ("stop_ark_and_delegate", "indexer_running", True),
            ("stop_ark_and_delegate", "recovery_network_restricted", False),
            ("erase_wallet", "retained_recovery_material", ["seed", "wallet_db"]),
            ("restore_and_fetch", "nostr_public_key", "00" * 32),
            ("restore_and_fetch", "ciphertext_sha256", "00" * 32),
            ("restore_and_fetch", "ark_requests", 1),
            ("restore_and_fetch", "delegate_requests", False),
            ("fund_exit", "fee_payer", "delegate"),
            ("fund_exit", "funding_confirmations", 0),
            ("exit_and_sweep", "sweep_confirmations", 0),
            ("exit_and_sweep", "received_sats", 0),
            ("exit_and_sweep", "spent_outpoint", "22" * 32 + ":0"),
            ("exit_and_sweep", "destination_verified_from_seed", False),
        ]
        for step, field, value in mutations:
            with self.subTest(step=step, field=field, value=value):
                evidence = valid_evidence()
                evidence[step][field] = value
                with self.assertRaises(run.Failed):
                    self.validate(evidence)


class RunnerTests(unittest.TestCase):
    def test_cleanup_after_partial_start_checks_resource_ownership(self):
        for label, should_remove in (("test-run", True), ("another-run", False)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                runner = run.Run(Path(temp))
                runner.id = "test-run"
                calls = []

                def command(name, argv, **kwargs):
                    calls.append(name)
                    if name == "bitcoin-start":
                        raise run.Failed("start reply lost after container creation")
                    if name == "bitcoin-owner":
                        return label
                    return ""

                runner.command = command
                with mock.patch.object(run.shutil, "which", return_value="docker"):
                    with self.assertRaises(run.Failed):
                        with run.bitcoin_node(runner, "test-image"):
                            self.fail("startup must fail")
                self.assertEqual("bitcoin-cleanup" in calls, should_remove)

    def test_skipped_or_unselected_go_tests_cannot_pass(self):
        for log in ("", '{"Action":"pass","Package":"example"}', '{"Action":"skip","Test":"Required"}'):
            with self.assertRaises(run.Failed):
                run.require_go_tests(log, {"Required"})
        run.require_go_tests('{"Action":"pass","Test":"Required"}', {"Required"})

    def test_missing_driver_is_reported_blocked_with_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            code = run.main(["acceptance", "--output", temp])
            self.assertEqual(code, 2)
            folder = next(Path(temp).iterdir())
            report = json.loads((folder / "report.json").read_text())
            self.assertEqual(report["full_acceptance"], "blocked")
            self.assertEqual(ET.parse(folder / "junit.xml").getroot().get("skipped"), "1")

    def test_simulated_driver_cannot_satisfy_live_acceptance(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            script = root / "driver.py"
            script.write_text('import sys,json\nr=json.load(sys.stdin)\nr.update(status="ok",evidence={"mode":"simulated","actions":[]})\nprint(json.dumps(r))\n')
            config = root / "driver.json"
            config.write_text(json.dumps({"argv": [sys.executable, str(script)]}))
            self.assertEqual(run.main(["acceptance", "--output", str(root / "results"), "--driver", str(config)]), 2)

    def test_stale_driver_response_is_failure(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            script = root / "stale.py"
            script.write_text('import sys,json\nr=json.load(sys.stdin)\nr.update(status="ok",nonce="old-response",evidence={})\nprint(json.dumps(r))\n')
            config = root / "driver.json"
            config.write_text(json.dumps({"argv": [sys.executable, str(script)]}))
            self.assertEqual(run.main(["acceptance", "--output", str(root / "results"), "--driver", str(config)]), 1)

    def test_timeout_stops_command(self):
        with tempfile.TemporaryDirectory() as temp:
            runner = run.Run(Path(temp), timeout=0.1)
            with self.assertRaises(run.Failed):
                runner.command("sleep", [sys.executable, "-c", "import time;time.sleep(30)"])

    def test_failing_command_and_unexpected_exception_are_not_green(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            runner = run.Run(Path(temp))
            status = runner.case("failure", "selftest", lambda: runner.command("exit", [sys.executable, "-c", "raise SystemExit(7)"]))
            self.assertEqual(status, "failed")
            status = runner.case("exception", "selftest", lambda: 1 / 0)
            self.assertEqual(status, "failed")
            self.assertEqual(json.loads((runner.directory / "report.json").read_text())["full_acceptance"], "not_run")

    def test_inherited_bitcoin_settings_are_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            prior = os.environ.get("RECOVERY_BITCOIN_RPC_URL")
            try:
                os.environ["RECOVERY_BITCOIN_RPC_URL"] = "http://do-not-touch"
                runner = run.Run(Path(temp))
                self.assertNotIn("RECOVERY_BITCOIN_RPC_URL", runner.env)
                self.assertEqual(runner.directory.stat().st_mode & 0o777, 0o700)
            finally:
                if prior is None:
                    del os.environ["RECOVERY_BITCOIN_RPC_URL"]
                else:
                    os.environ["RECOVERY_BITCOIN_RPC_URL"] = prior


if __name__ == "__main__":
    unittest.main()
