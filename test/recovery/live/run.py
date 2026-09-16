#!/usr/bin/env python3
"""Recovery test orchestration. Standard library only; never uses a shared stack."""
from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET

from paths import BACKUP, FULMINE, HARNESS
IMAGE = "bitcoin/bitcoin@sha256:68b927b6a2d3b019ce7655f3fd0eb9a4c7011310886ebc7890e5246c16df5ec6"
MAX_LOG = 16 * 1024 * 1024
COMPONENT_TESTS = {
    "TestEncryptedEnvelope", "TestOutboxLostReplyAndRestart",
    "TestBranchValidation", "TestBackupServerIntegration", "TestCommittedUploadLostResponse",
}
STEPS = (
    "setup", "prepare_wallet", "stop_wallet", "refresh_and_backup",
    "stop_ark_and_delegate", "erase_wallet", "restore_and_fetch",
    "fund_exit", "exit_and_sweep",
)


class Blocked(Exception):
    pass


class Failed(Exception):
    pass


def checked(condition, reason):
    if not condition:
        raise Failed(reason)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def txid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def outpoint(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}:[0-9]+", value) is not None


def validate_step(step, data, previous):
    """Acceptance assertions, independent of the future wallet/stack adapter.

    The adapter must implement and observe real processes/Bitcoin. These checks
    validate its evidence; they do not turn a simulated adapter into a live test.
    """
    checked(isinstance(data, dict), "step evidence must be an object")
    if step == "setup":
        checked(data.get("chain") == "regtest", "live acceptance requires regtest")
        checked(data.get("isolated") is True, "driver must own an isolated stack")
    elif step == "prepare_wallet":
        checked(txid(data.get("nostr_public_key")), "missing recovery identity")
        checked(outpoint(data.get("original_outpoint")), "missing original VTXO")
        checked(type(data.get("fee_balance_sats")) is int and data["fee_balance_sats"] == 0, "wallet must start without fee funds")
        checked(data.get("baseline_backed_up") is True, "original recovery baseline missing")
    elif step == "stop_wallet":
        checked(data.get("wallet_running") is False, "wallet must be offline during refresh")
    elif step == "refresh_and_backup":
        checked(outpoint(data.get("replacement_outpoint")), "replacement VTXO missing")
        checked(data["replacement_outpoint"] != previous["prepare_wallet"]["original_outpoint"], "refresh must replace the original outpoint")
        checked(txid(data.get("commitment_txid")) and txid(data.get("ciphertext_sha256")), "missing commitment or backup commitment")
        checked(integer(data.get("commitment_confirmations"), 1), "replacement commitment must confirm")
        ack, forfeit = data.get("backup_ack_sequence"), data.get("forfeit_submit_sequence")
        checked(integer(ack, 1) and integer(forfeit, 1) and ack < forfeit, "backup acknowledgement must precede forfeits")
        checked(data.get("wallet_running") is False, "refresh used the online wallet")
        checked(type(data.get("fee_balance_sats")) is int and data["fee_balance_sats"] == 0, "fee funding occurred before backup")
    elif step == "stop_ark_and_delegate":
        for field in ("ark_running", "indexer_running", "delegate_running"):
            checked(data.get(field) is False, f"{field} must be false")
        checked(data.get("backup_running") is True and data.get("bitcoin_running") is True, "backup and Bitcoin must survive")
        checked(data.get("recovery_network_restricted") is True, "recovery must have no route to Arkade/delegate")
    elif step == "erase_wallet":
        checked(data.get("wallet_state_removed") is True, "wallet state was not erased")
        checked(data.get("retained_recovery_material") == ["seed"], "only the seed may survive wallet erasure")
    elif step == "restore_and_fetch":
        checked(data.get("nostr_public_key") == previous["prepare_wallet"]["nostr_public_key"], "seed restored a different identity")
        checked(data.get("replacement_outpoint") == previous["refresh_and_backup"]["replacement_outpoint"], "restored the wrong VTXO")
        checked(data.get("ciphertext_sha256") == previous["refresh_and_backup"]["ciphertext_sha256"], "retrieved a different backup")
        checked(data.get("bitcoin_signatures_verified") is True, "restored branch not verified")
        checked(data.get("owner_authenticated_fetch") is True, "fetch lacked owner authentication")
        checked(type(data.get("fee_balance_sats")) is int and data["fee_balance_sats"] == 0, "fees were supplied before retrieval")
        no_ark_access(data)
    elif step == "fund_exit":
        checked(txid(data.get("funding_txid")), "missing later funding transaction")
        checked(integer(data.get("funding_confirmations"), 1) and integer(data.get("funding_sats"), 1), "fee funding must be confirmed")
        checked(data.get("fee_payer") == "user", "fee sponsorship is excluded")
        no_ark_access(data)
    elif step == "exit_and_sweep":
        checked(txid(data.get("sweep_txid")), "no final Bitcoin sweep")
        checked(integer(data.get("sweep_confirmations"), 1) and integer(data.get("received_sats"), 1), "final payout not confirmed")
        checked(data.get("spent_outpoint") == previous["refresh_and_backup"]["replacement_outpoint"], "sweep did not spend the replacement")
        checked(data.get("destination_verified_from_seed") is True, "sweep destination not owned by the restored seed")
        checked(data.get("fee_payer") == "user", "executor paid the fees")
        no_ark_access(data)


def no_ark_access(data):
    for name in ("ark_requests", "delegate_requests"):
        checked(type(data.get(name)) is int and data[name] == 0, f"unexpected {name} during independent recovery")


@dataclasses.dataclass
class Result:
    name: str
    scope: str
    status: str
    seconds: float
    detail: str = ""


class Run:
    def __init__(self, output: Path, timeout=300):
        self.id = uuid.uuid4().hex
        self.directory = output.expanduser().resolve() / self.id
        self.directory.mkdir(parents=True, mode=0o700)
        self.timeout = timeout
        self.results = []
        self.env = os.environ.copy()
        # Never inherit access to somebody else's Bitcoin node or evidence file.
        for key in list(self.env):
            if key.startswith(("RECOVERY_BITCOIN_", "RECOVERY_LIVE_", "RECOVERY_TEST_")) or key == "BACKUP_PROTOTYPE_BIN":
                self.env.pop(key)
        local_go = FULMINE.parent / ".tools/go/bin"
        if (local_go / "go").exists():
            self.env["PATH"] = str(local_go) + os.pathsep + self.env.get("PATH", "")
        self.env["BACKUP_PROTOTYPE_BIN"] = str(BACKUP / "target/debug/arkade-recovery-prototype")

    def command(self, name, argv, cwd=FULMINE, env=None, input_data=None, timeout=None):
        """Bounded command; argv only, never shell interpolation. Logs stay private."""
        path = self.directory / f"{name}.log"
        with open(path, "wb", opener=lambda p, flags: os.open(p, flags, 0o600)) as output:
            try:
                process = subprocess.Popen(argv, cwd=cwd, env=env or self.env,
                                           stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            except FileNotFoundError as exc:
                raise Blocked(f"required executable missing: {argv[0]}") from exc
            try:
                if input_data is not None:
                    process.stdin.write(input_data)
                    process.stdin.close()
                deadline = time.monotonic() + (timeout or self.timeout)
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise Failed(f"{name} exceeded its timeout; see {path.name}")
                    if os.fstat(output.fileno()).st_size > MAX_LOG:
                        raise Failed(f"{name} exceeded its log bound")
                    time.sleep(0.05)
                checked(process.returncode == 0, f"{name} exited {process.returncode}; see {path.name}")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
        checked(path.stat().st_size <= MAX_LOG, f"{name} exceeded its log bound")
        return path.read_text(errors="replace")

    def case(self, name, scope, function):
        print(f"RUN {name} ({scope})", flush=True)
        start = time.monotonic()
        try:
            function()
            result = Result(name, scope, "passed", time.monotonic() - start)
        except Blocked as exc:
            result = Result(name, scope, "blocked", time.monotonic() - start, str(exc))
        except (Failed, OSError, ValueError, RuntimeError) as exc:
            result = Result(name, scope, "failed", time.monotonic() - start, str(exc))
        except Exception as exc:
            result = Result(name, scope, "failed", time.monotonic() - start, "unexpected harness error: " + type(exc).__name__)
        self.results.append(result)
        print(f"{result.status.upper()} {name}" + (f": {result.detail}" if result.detail else ""), flush=True)
        self.report()
        return result.status

    def report(self):
        acceptance = next((r.status for r in self.results if r.scope == "full_acceptance"), "not_run")
        report = {"version": 1, "run_id": self.id, "full_acceptance": acceptance,
                  "results": [dataclasses.asdict(r) for r in self.results]}
        if hasattr(self, "build_manifest"):
            report["build"] = self.build_manifest
        if hasattr(self, "live_refresh_summary"):
            report["live_refresh"] = self.live_refresh_summary
        import coverage
        edge_cases = coverage.report(self.directory)
        (self.directory / "edge-cases.json").write_text(json.dumps(edge_cases, indent=2) + "\n")
        report["edge_case_summary"] = {state: sum(case["status"] == state for case in edge_cases["cases"]) for state in ("passed", "failed", "not_run", "unimplemented")}
        (self.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        suite = ET.Element("testsuite", name="arkade-recovery", tests=str(len(self.results)),
                           failures=str(sum(r.status == "failed" for r in self.results)),
                           skipped=str(sum(r.status == "blocked" for r in self.results)))
        for result in self.results:
            case = ET.SubElement(suite, "testcase", name=result.name, classname=result.scope, time=f"{result.seconds:.3f}")
            if result.status != "passed":
                ET.SubElement(case, "failure" if result.status == "failed" else "skipped", message=result.detail)
        ET.ElementTree(suite).write(self.directory / "junit.xml", encoding="utf-8", xml_declaration=True)


def require_go_tests(log, expected):
    observed = {}
    for line in log.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Test") in expected and event.get("Action") in {"pass", "fail", "skip"}:
            observed[event["Test"]] = event["Action"]
    for name in expected:
        checked(observed.get(name) == "pass", f"required test {name} did not run and pass (observed {observed.get(name, 'missing')})")


def build(run):
    run.command("build-backup", ["cargo", "build", "--bin", "arkade-recovery-prototype"], BACKUP)


def components(run):
    run.command("rust-tests", ["cargo", "test", "--locked"], BACKUP)
    run.command("rust-lints", ["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"], BACKUP)
    build(run)
    log = run.command("recovery-components", ["go", "test", "-json", "-count=1", "-race", "./pkg/recovery"], FULMINE)
    require_go_tests(log, COMPONENT_TESTS)
    run.command("fulmine-tests", ["go", "test", "-json", "-count=1", "./internal/core/application", "./internal/interface/grpc/handlers", "./internal/infrastructure/db/...", "./cmd/recovery-client"], FULMINE)
    run.command("fulmine-build", ["go", "build", "./cmd/fulmine", "./cmd/recovery-client"], FULMINE)


def rpc_ready(url, user, password):
    request = urllib.request.Request(url, json.dumps({"jsonrpc": "1.0", "id": 1, "method": "getblockchaininfo", "params": []}).encode())
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    with urllib.request.urlopen(request, timeout=1) as response:
        result = json.load(response)
    return result.get("result", {}).get("chain") == "regtest"


@contextlib.contextmanager
def bitcoin_node(run, image):
    if not shutil.which("docker", path=run.env["PATH"]):
        raise Blocked("Docker is required for the isolated Bitcoin test")
    try:
        run.command("docker-check", ["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
        run.command("bitcoin-image", ["docker", "image", "inspect", image, "--format", "{{.Id}}"], timeout=15)
    except Failed as exc:
        raise Blocked("Docker or the pinned Bitcoin image is unavailable; see prerequisite logs (no automatic image pull)") from exc
    name = "bull-recovery-" + run.id
    user, password = "recovery", secrets.token_hex(24)
    started = False
    attempted = False
    try:
        # No fixed names, existing networks, persistent volumes, P2P or public ports.
        attempted = True
        run.command("bitcoin-start", ["docker", "run", "--detach", "--name", name,
            "--label", "bull.recovery.run=" + run.id, "--pull=never", "--tmpfs", "/testdata:rw,mode=1777",
            "--publish", "127.0.0.1::18443", image, "bitcoind", "-datadir=/testdata",
            "-regtest=1", "-server=1", "-listen=0", "-discover=0", "-dnsseed=0", "-connect=0",
            "-txindex=1", "-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0", "-rpcuser=" + user,
            "-rpcpassword=" + password, "-fallbackfee=0.00002"], timeout=30)
        started = True
        binding = run.command("bitcoin-port", ["docker", "port", name, "18443/tcp"], timeout=10).strip()
        checked(re.fullmatch(r"127\.0\.0\.1:[0-9]+", binding), "unexpected Bitcoin port binding")
        url = "http://" + binding
        deadline = time.monotonic() + 45
        while True:
            try:
                if rpc_ready(url, user, password):
                    break
            except (OSError, ValueError, urllib.error.URLError):
                pass
            checked(time.monotonic() < deadline, "isolated Bitcoin node did not become ready")
            time.sleep(0.2)
        env = run.env.copy()
        env.update(RECOVERY_BITCOIN_RPC_URL=url, RECOVERY_BITCOIN_RPC_USER=user,
                   RECOVERY_BITCOIN_RPC_PASSWORD=password,
                   RECOVERY_BITCOIN_EVIDENCE=str(run.directory / "bitcoin-evidence.json"))
        yield env
    finally:
        if attempted:
            # Cleanup only a resource bearing this run's unpredictable ownership label.
            try:
                label = run.command("bitcoin-owner", ["docker", "inspect", "--format", '{{index .Config.Labels "bull.recovery.run"}}', name], timeout=10).strip()
            except Failed:
                # A failed docker run may not have created a container. If it
                # did return success, inability to verify cleanup is a failure.
                if started:
                    raise
            else:
                checked(label == run.id, "refusing to remove a container owned by another run")
                run.command("bitcoin-cleanup", ["docker", "rm", "-f", "-v", name], timeout=20)


def bitcoin(run, image):
    build(run)
    with bitcoin_node(run, image) as env:
        log = run.command("bitcoin-late-funding", ["go", "test", "-json", "-count=1", "-timeout=150s", "-run", "^TestBitcoinLateFunding$", "./pkg/recovery"], FULMINE, env=env, timeout=180)
        require_go_tests(log, {"TestBitcoinLateFunding"})
        evidence = json.loads((run.directory / "bitcoin-evidence.json").read_text())
        checked(evidence.get("confirmed") is True and evidence.get("late_funding") is True, "missing confirmed later-funded Bitcoin exit evidence")
        checked(evidence.get("arkd_round") is False, "Bitcoin fixture must not claim to be an Arkade round")


def acceptance(run, driver_config):
    if driver_config is None:
        raise Blocked("live wallet/arkd adapter is not implemented; see test/recovery/live/DRIVER.md. Component and Bitcoin fixture success cannot satisfy full acceptance")
    config = json.loads(driver_config.read_text())
    argv = config.get("argv")
    checked(isinstance(argv, list) and bool(argv) and all(isinstance(v, str) for v in argv), "driver argv must be a nonempty array of strings")
    evidence = {}

    def call(action):
        nonce = secrets.token_hex(16)
        request = {"version": 1, "run_id": run.id, "nonce": nonce, "action": action,
                   "workdir": str(run.directory / "driver-state")}
        log = run.command("acceptance-" + action, argv, input_data=json.dumps(request).encode())
        try:
            reply = json.loads(log)
        except ValueError as exc:
            raise Failed("driver must return one JSON response without log chatter") from exc
        checked(reply.get("version") == 1 and reply.get("run_id") == run.id and reply.get("nonce") == nonce, "driver response has stale or mismatched request identity")
        if reply.get("status") == "blocked":
            raise Blocked("driver cannot perform " + action)
        checked(reply.get("status") == "ok", "driver failed " + action)
        return reply.get("evidence", {})

    caps = call("capabilities")
    if caps.get("mode") != "live" or not set(STEPS + ("cleanup",)).issubset(set(caps.get("actions", []))):
        raise Blocked("driver lacks real-stack support for all required actions; simulated results are not acceptance")
    (run.directory / "driver-state").mkdir(mode=0o700)
    try:
        for step in STEPS:
            print("  acceptance: " + step, flush=True)
            data = call(step)
            validate_step(step, data, evidence)
            evidence[step] = data
        # Driver responses must contain public regtest evidence, never seeds/keys.
        (run.directory / "acceptance-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    finally:
        call("cleanup")


def live_case(run, binaries, backup_outage, refresh_count):
    import live
    blocked_reason = live.acceptance(run, binaries, backup_outage, refresh_count)
    if refresh_count > 1:
        checked(isinstance(blocked_reason, str) and bool(blocked_reason.strip()),
                "offline renewal probe must report its observed boundary; one refresh cannot satisfy multiple refreshes")
        raise Blocked(blocked_reason)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("components", "bitcoin", "live", "fuzz", "acceptance", "all", "list"))
    parser.add_argument("--output", type=Path, default=HARNESS / "artifacts")
    parser.add_argument("--bitcoin-image", default=IMAGE, help="already installed image; default is pinned by digest")
    parser.add_argument("--driver", type=Path, help="JSON {argv:[...]} for a real live-stack adapter")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--live-binaries", type=Path, help="prebuilt live fixture binaries for an isolated VM runner")
    parser.add_argument("--live-backup-outage", action="store_true", help="kill the live backup before refresh and require the original VTXO to remain unspent")
    parser.add_argument("--live-refresh-count", type=int, default=1, choices=range(1, 11), help="requested consecutive refreshes with the wallet offline (1..10); unsupported renewal reports blocked after testing exit of the last completed coin")
    args = parser.parse_args(argv)
    if args.live_refresh_count > 1 and (args.live_backup_outage or args.suite != "live"):
        parser.error("--live-refresh-count greater than one requires the live suite without --live-backup-outage")
    if args.suite == "list":
        print("components: real Go/Rust protocol, durability and authentication tests\nbitcoin: isolated Core node, encrypted branch retrieval, later funding, CSV sweep\nlive: real delegated refresh and independent exit; --live-backup-outage checks the backup gate\nfuzz: bounded recovery-record fuzzing\nacceptance: complete wallet restoration flow (requires wallet adapter)\nall: components, bitcoin, acceptance; missing adapter returns exit code 2")
        return 0
    run = Run(args.output, args.timeout)
    try:
        if args.suite in ("components", "all"):
            run.case("component_checks", "components", lambda: components(run))
        if args.suite in ("bitcoin", "all"):
            run.case("bitcoin_later_funding", "bitcoin_fixture", lambda: bitcoin(run, args.bitcoin_image))
        if args.suite == "fuzz":
            run.case("recovery_record_fuzz", "fuzz", lambda: run.command("record-fuzz", ["go", "test", "-run=^$", "-fuzz=^FuzzRecoveryRecord$", "-fuzztime=15s", "-parallel=2", "./pkg/recovery"], FULMINE, timeout=60))
        if args.suite == "live":
            name = "live_backup_outage_preserves_original" if args.live_backup_outage else "live_delegated_refresh_to_exit"
            if args.live_refresh_count > 1:
                name = "live_offline_successive_refreshes_to_exit"
            run.case(name, "live_delegate", lambda: live_case(run, args.live_binaries, args.live_backup_outage, args.live_refresh_count))
        if args.suite in ("acceptance", "all"):
            run.case("delegated_refresh_to_exit", "full_acceptance", lambda: acceptance(run, args.driver))
    except KeyboardInterrupt:
        run.results.append(Result("interrupted", "harness", "failed", 0, "interrupted; owned resources were cleaned where possible"))
    finally:
        run.report()
        print("Report: " + str(run.directory / "report.json"), flush=True)
    if any(r.status == "failed" for r in run.results):
        return 1
    if any(r.status == "blocked" for r in run.results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
