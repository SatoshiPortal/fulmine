#!/usr/bin/env python3
"""Required backend component checks on an isolated CI runner; no deployment."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time

from remote import GATES, REQUIRED, execute_command, verify_tests

INTEGRATED_TEST = "tests::integrated_recovery_uses_shared_storage_and_preserves_historical_fetch"
RUST_REQUIRED = {"recovery::tests::shared_wire_conformance_vector", INTEGRATED_TEST}
GO_REQUIRED = REQUIRED | GATES | {"TestRecoveryWireConformance", "TestRecoveryBundleWireConformance",
                                 "TestRecoveryRegistrationSurvivesRestart", "TestSendOffChainWithRecovery",
                                 "TestProtectedAttemptCrashProcess", "TestProtectedRecoveryLegacyAndUnavailableStorage",
                                 "TestProtectedGatePersistenceFailurePreventsSubmission",
                                 "TestProtectedActiveRetryDoesNotQuarantineRunningAttempt",
                                 "TestProtectedRegistrationNetworkGate", "TestProtectedStreamTerminationPreservesUncertainty",
                                 "TestProtectedAttemptPersistenceAndTampering", "TestProtectedAttemptClaimAndStorageFailure",
                                 "TestProtectedFinalizedEvidenceSurvivesLaterStreamEvents",
                                 "TestRetainedOutboxAssociationAuthenticatesBeforeScheduling",
                                 "TestProtectedAttemptCumulativeByteLimit", "TestProtectedAttemptCancellationAfterAcquire"}


def verify_rust(output: str) -> list[str]:
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))
    missing = RUST_REQUIRED - passed
    if missing:
        raise RuntimeError(f"required Rust tests did not pass: {sorted(missing)}")
    return sorted(RUST_REQUIRED)


def check_fixtures(fulmine: Path, backup: Path) -> str:
    canonical = (fulmine / "test/recovery/fixtures/recovery-wire-v1.json").read_bytes()
    companion = (backup / "tests/fixtures/recovery-wire-v1.json").read_bytes()
    if canonical != companion:
        raise RuntimeError("companion recovery fixture differs from canonical bytes")
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    fulmine = Path(__file__).resolve().parents[2]
    backup = args.backup_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "backend_components", "status": "failed", "sources": {}, "skipped_go_tests": []}
    started = time.monotonic()
    # A component run must not inherit access to a live node or another test process.
    unset = ["--unset=" + key for key in os.environ
             if key.startswith(("RECOVERY_BITCOIN_", "RECOVERY_LIVE_", "RECOVERY_TEST_"))
             or key in {"BACKUP_PROTOTYPE_BIN", "CARGO_TARGET_DIR"}]

    def run(label: str, cwd: Path, argv: list[str], timeout: int = 900) -> str:
        return execute_command(output / (label + ".log"),
                               ["env", *unset, "-C", str(cwd), *argv], timeout=timeout)

    def clean_source(name: str, path: Path, phase: str) -> None:
        status = run(name + "-" + phase + "-status", path,
                     ["git", "status", "--porcelain", "--untracked-files=normal"])
        if status.strip():
            raise RuntimeError(f"{name} worktree is dirty {phase}; release checks require exact revisions")

    try:
        report["fixture_sha256"] = check_fixtures(fulmine, backup)
        for name, path in (("fulmine", fulmine), ("backup", backup)):
            report["sources"][name] = run(name + "-revision", path, ["git", "rev-parse", "HEAD"]).strip()
            clean_source(name, path, "before")
        report["go_version"] = run("go-version", fulmine, ["go", "version"]).strip()
        report["rust_version"] = run("rust-version", backup, ["rustc", "--version"]).strip()
        run("rust-fmt", backup, ["cargo", "fmt", "--all", "--", "--check"])
        run("rust-clippy", backup, ["cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings"])
        rust = run("rust-tests", backup, ["cargo", "test", "--all-targets", "--locked"])
        report["rust_required_passes"] = verify_rust(rust)
        run("backup-build", backup, ["cargo", "build", "--locked", "--bin", "backup-server",
                                     "--bin", "arkade-recovery-prototype"])
        binaries = {name: backup / "target/debug" / name for name in ("backup-server", "arkade-recovery-prototype")}
        report["binary_sha256"] = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                    for name, path in binaries.items()}
        go = run("go-tests", fulmine,
                 ["env", "GOFLAGS=-mod=readonly", "BACKUP_PROTOTYPE_BIN=" + str(binaries["arkade-recovery-prototype"]),
                  "go", "test", "-race", "-count=1", "-v", "-timeout=5m", "./pkg/recovery",
                  "./internal/core/application", "./internal/infrastructure/db/...",
                  "./internal/interface/grpc/handlers", "./cmd/recovery-client"])
        report["go_required_passes"] = verify_tests(go, GO_REQUIRED, 1)
        report["skipped_go_tests"] = re.findall(r"^--- SKIP: (\S+)", go, re.MULTILINE)
        run("go-vet", fulmine, ["env", "GOFLAGS=-mod=readonly", "go", "vet", "./pkg/recovery",
                                "./internal/core/application", "./internal/infrastructure/db/...",
                                "./internal/interface/grpc/handlers", "./cmd/recovery-client"])
        run("runner-tests", fulmine, ["python3", "-m", "unittest", "discover", "-s", "test/recovery", "-p", "test_*.py"])
        for name, path in (("fulmine", fulmine), ("backup", backup)):
            clean_source(name, path, "after")
        report["status"] = "passed"
    except (OSError, RuntimeError) as exc:
        report["error"] = str(exc)
    finally:
        report["seconds"] = round(time.monotonic() - started, 3)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": report["scope"], "report": str(output / "report.json")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    os.environ["CARGO_TERM_COLOR"] = "never"
    raise SystemExit(main())
