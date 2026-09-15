# Backend recovery release checks

The `Recovery conformance` workflow runs on all pull requests, master and recovery
branch pushes, and manual dispatch. Its `Backend recovery components` job tests
the candidate with one exact companion revision. It uses read-only repository
permissions, no deployment secrets, and no paid runner provisioning.

Repository administrators must select this job as a required branch-protection
check before describing it as an enforced merge gate. Adding the workflow does
not configure protection. Existing release publishing workflows are unchanged;
operators must review the evidence below before publishing or deploying.

## Component evidence

On an isolated Ubuntu 24.04 runner, with the toolchains specified by `go.mod` and
`rust-toolchain.toml`, run from a clean Fulmine checkout:

```sh
python3 test/recovery/backend_ci.py \
  --backup-root /absolute/path/to/BULL-metadata-backup \
  --output /absolute/path/outside/checkouts/new-evidence-directory
```

The output directory must not already exist. The helper rejects dirty checkouts,
records both Git revisions and the shared fixture hash, then runs:

- byte comparison of the two `recovery-wire-v1.json` copies;
- Rust formatting, clippy with warnings denied, and all-target tests, locked;
- explicit required passes for the Rust wire vector and the main-listener shared
  storage / historical-fetch integration test;
- builds of the main `backup-server` and compatibility
  `arkade-recovery-prototype` executables, recording both hashes;
- Go race tests across recovery, application, SQLite/Badger, gRPC handlers and
  recovery client packages, with the freshly built Rust companion available;
- explicit required passes for the Go wire/bundle vectors, backup fault and
  pre-forfeit gate cases, registration restart and protected send cases;
- Go vet and the Python runner self-tests, followed by clean-source checks.

The final `report.json` must say `passed`. A missing binary, different fixture,
filtered/ignored required test, subprocess timeout or dirty source fails the job.
Fixture-dependent live/Bitcoin tests are listed as skipped: component success
is not evidence of a confirmed Bitcoin exit. The compatibility executable still
serves cross-language fault tests; the main resource is separately required by
its integration test. Do not remove either until those tests are migrated.

The helper reuses the existing bounded runner (15-minute command deadlines,
16-MiB per-command logs). Ambient recovery test/live-node settings are removed.
It starts isolated test listeners; use an approved VM or hosted CI runner when
local policy prohibits listeners. It never targets a deployed service.

## Pairing repositories

Both `.github/workflows/recovery.yml` files pin the companion by full commit SHA.
Review dependency and fixture changes in both repositories, then update the pins.
Do not replace them with a moving branch or disable missing-test checks to make
an incompatible pair green.

For the first integrated release, publish the backup runtime/tests commit first;
publish Fulmine's helper/workflow and runtime commit with that backup pin next;
then publish the backup workflow pinned to that Fulmine commit. The initial
backup runtime commit is checked by Fulmine even before it carries the new CI
workflow. Record the two revisions from each passing report; subsequent releases
must similarly test each changed runtime against the intended companion.

The canonical fixture is maintained in Fulmine; see
[the wire contract](recovery-wire-v1.md). When intentionally changing fixture
coverage, regenerate it there, review the exact bytes, copy it to backup and
wallet, run all three language conformance tests, and update their reviewed pins.
Passing backend CI alone says nothing about a wallet revision not tested with it.

## Release artifacts and deployment

Build release executables from the recorded clean commits and locked dependencies.
Retain source revisions, toolchain versions and SHA-256 hashes in the existing
`build-manifest.json` format used by the live runner. CI's debug executable hashes
identify its component run only; they are not the release executable hashes.

Before deployment, use the existing [fault runner](../test/recovery/remote.py)
with the release's race-test executables and Rust companion, and run both concrete
scenarios from [the live runbook](../test/recovery/live/README.md) on an isolated
VM: `live` and `live --live-backup-outage`, supplying `--live-binaries` for the
release artifact directory. Install only the pinned container images explicitly
beforehand. Retain the runner reports, manifest, confirmed exit evidence and
successful cleanup result. An adapter-dependent `acceptance` or `all` result is
not a substitute for the concrete scenarios. Fuzzing supplements these checks.

For the integrated metadata server, additionally verify an operational database
backup restores metadata and recovery records, accounting and historical fetch
on another isolated instance. Follow that version's migration instructions;
an older binary that cannot read the new schema is not a valid rollback target.
Preserve existing database, owner configuration and service configuration during
deployment. Record actual running executable hashes and post-restart readiness;
repeat the authenticated recovery smoke check using that deployed revision.

Upload only reviewed logs and compact reports. Live artifact directories can
contain seeds and wallet state; do not publish them wholesale. CI retains its
component logs/report for 14 days. A passing release pair does not establish
unlimited offline renewals, host-loss durability, wallet automatic enrollment,
or mainnet readiness; those require their own recorded acceptance evidence.
