#!/usr/bin/env python3
"""Run isolated recovery fault tests on an SSH-accessible VM."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import time
import uuid

REQUIRED = {
    "TestBackupServerIntegration", "TestCommittedUploadLostResponse",
    "TestPublisherOwnershipAndKeyValidation", "TestDeliveryLockHonorsCancellation",
    "TestReceiptAndLocalWriteFailures", "TestEnvelopeTamperingMatrix",
    "TestEnvelopeAuthenticatedBadCiphertext", "TestBranchAdversarialMatrix",
    "TestFetchResumeAndLocalIntegrity", "TestFetchRejectsMalformedPages",
    "TestBackupCrashAndSeedRecovery",
    "TestBackupResponseBoundaries", "TestBackupRedirectDoesNotForwardAuthorization",
    "TestBackupStalledResponseHonorsCancellation",
}
GATES = {
    "TestRecoveryGateOrdersAndBindsCandidate", "TestRecoveryGateRejectsFailuresBeforeSubmission",
    "TestRecoveryGateMissingConnectors", "TestRecoverySubmissionLostResponse",
    "TestRecoveryGateBatchFailureRevokesReadiness", "TestRecoveryDisabledCompletion",
    "TestRecoveryNetworkBoundary",
}


def execute_command(path: Path, argv: list[str], timeout: float = 300,
                    max_bytes: int = 16 * 1024 * 1024) -> str:
    """Bound output as it arrives and reap the command's entire process group."""
    deadline = time.monotonic() + timeout
    with path.open("xb") as log:
        os.chmod(path, 0o600)
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(f"{path.stem} timed out after {timeout}s; see {path}")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = max_bytes - total
                        log.write(chunk[:available])
                        log.flush()
                        total += len(chunk)
                        if total > max_bytes:
                            raise RuntimeError(f"{path.stem} exceeded log limit; see {path}")
            try:
                result = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{path.stem} timed out after {timeout}s; see {path}") from exc
            if result:
                raise RuntimeError(f"{path.stem} exited {result}; see {path}")
        finally:
            # Children may retain stdout or outlive a successful parent.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
    return path.read_text(errors="replace")


def verify_tests(output: str, expected: set[str], repeats: int) -> dict[str, int]:
    if re.search(r"^--- FAIL:|^FAIL$|^panic:", output, re.MULTILINE):
        raise RuntimeError("remote test reported a failure")
    counts = {name: len(re.findall(r"^--- PASS: " + re.escape(name) + r" \(", output, re.MULTILINE)) for name in expected}
    missing = {name: count for name, count in counts.items() if count != repeats}
    if missing:
        raise RuntimeError(f"required test execution counts differ from {repeats}: {missing}")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-config", required=True, type=Path)
    parser.add_argument("--host", required=True, help="SSH config alias for the test VM")
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "artifacts")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--fuzz-binary", type=Path,
                        help="optional Go test binary built with go test -c -fuzz=FuzzRecoveryRecord")
    parser.add_argument("--fuzz-seconds", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 20:
        parser.error("repeat must be between 1 and 20")
    if not 1 <= args.fuzz_seconds <= 300:
        parser.error("fuzz-seconds must be between 1 and 300")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", args.host):
        parser.error("host must be an SSH config alias")
    run_id = uuid.uuid4().hex
    directory = args.output.resolve() / run_id
    directory.mkdir(parents=True, mode=0o700)
    remote = "/tmp/arkade-recovery-test-" + run_id
    ssh = ["ssh", "-F", str(args.ssh_config.resolve()), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", args.host]
    report = {"scope": "remote_components", "status": "failed", "run_id": run_id, "repeats": args.repeat, "tests": {}, "binary_sha256": {}}

    def execute(name: str, argv: list[str], timeout: int = 300) -> str:
        return execute_command(directory / (name + ".log"), argv, timeout)

    started = time.monotonic()
    try:
        execute("setup", ssh + [f"umask 077; mkdir {remote} && printf '%s' {run_id} > {remote}/.owner"])
        binaries = {name: args.binaries.resolve() / name for name in
                    ("recovery-tests", "application-tests", "arkade-recovery-prototype")}
        if args.fuzz_binary:
            binaries["recovery-fuzz"] = args.fuzz_binary.resolve()
        for name, binary in binaries.items():
            expected = hashlib.sha256(binary.read_bytes()).hexdigest()
            report["binary_sha256"][name] = expected
            execute("upload-" + name, ["scp", "-C", "-F", str(args.ssh_config.resolve()), "-o", "BatchMode=yes", str(binary), f"{args.host}:{remote}/{name}"], timeout=600)
            actual = execute("hash-" + name, ssh + [f"sha256sum {remote}/{name}"]).split()
            if not actual or actual[0] != expected:
                raise RuntimeError(name + " differs from the local build")
        for name, binary, expected in (("recovery", "recovery-tests", REQUIRED), ("gates", "application-tests", GATES)):
            pattern = "." if name == "recovery" else "^TestRecovery"
            env = f"env -i PATH=/usr/bin:/bin HOME={remote} TMPDIR={remote} BACKUP_PROTOTYPE_BIN={remote}/arkade-recovery-prototype"
            command = f"chmod 700 {remote}/* && {env} timeout --kill-after=5 180 {remote}/{binary} -test.v -test.count={args.repeat} -test.timeout=170s -test.run={shlex.quote(pattern)}"
            output = execute(name, ssh + [command], timeout=200)
            report["tests"].update(verify_tests(output, expected, args.repeat))
        for target in ("FuzzRecoveryRecord", "FuzzRecoveryEnvelope") if args.fuzz_binary else ():
            command = (f"cd {remote} && mkdir -p fuzz-cache && chmod 700 recovery-fuzz && "
                       f"env -i PATH=/usr/bin:/bin HOME={remote} TMPDIR={remote} "
                       f"timeout --kill-after=5 {args.fuzz_seconds + 30} ./recovery-fuzz -test.run='^$' "
                       f"-test.fuzz='^{target}$' -test.fuzztime={args.fuzz_seconds}s "
                       f"-test.parallel=2 -test.fuzzminimizetime=100ms -test.fuzzcachedir={remote}/fuzz-cache")
            try:
                output = execute("fuzz-" + target, ssh + [command], timeout=args.fuzz_seconds + 45)
            except (RuntimeError, OSError) as exc:
                log = directory / ("fuzz-" + target + ".log")
                failed = re.findall(r"testdata/fuzz/" + target + r"/[0-9a-f]{16,64}",
                                    log.read_text(errors="replace") if log.exists() else "")
                if failed:
                    try:
                        execute("reproducer-" + target, ssh + [f"cat -- {remote}/{failed[-1]}"], timeout=30)
                        report.setdefault("fuzz_reproducers", []).append("reproducer-" + target + ".log")
                    except (RuntimeError, OSError) as copy_error:
                        report["reproducer_error"] = str(copy_error)
                raise exc
            counts = re.findall(r"execs: ([0-9]+)", output)
            if not counts or int(counts[-1]) == 0 or not re.search(r"^PASS$", output, re.MULTILINE):
                raise RuntimeError("fuzz run did not report successful mutation executions")
            report.setdefault("fuzz_executions", {})[target] = int(counts[-1])
        report["status"] = "passed"
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        report["error"] = str(exc)
    finally:
        try:
            execute("cleanup", ssh + [f"if test -d {remote}; then test \"$(cat {remote}/.owner)\" = {run_id} && rm -rf -- {remote}; fi"], timeout=30)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            report["status"] = "failed"
            report["cleanup_error"] = str(exc)
        report["seconds"] = round(time.monotonic() - started, 3)
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": report["scope"], "report": str(directory / "report.json")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
