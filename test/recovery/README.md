# Recovery fault tests on a VM

This runner uploads compiled tests and the Rust recovery backup prototype to a
temporary directory on an existing Linux VM. It runs the recovery package and
delegate gate tests repeatedly, checks the exact required execution counts, and
removes its temporary directory. It does not restart deployment services or use
their databases.

Prepare three binaries in a private build directory:

- `recovery-tests`: `go test -c -race -o <build-dir>/recovery-tests ./pkg/recovery`
- `application-tests`: `go test -c -race -o <build-dir>/application-tests ./internal/core/application`
- `arkade-recovery-prototype`: the executable built from the matching
  `SatoshiPortal/BULL-metadata-backup` prototype branch.

Then run from the Fulmine repository:

```sh
python3 test/recovery/remote.py --ssh-config <private-ssh-config> --host <test-vm-alias> --binaries <build-dir> --repeat 5
```

The SSH configuration must select an available private key and verify the VM's
host key. The VM needs `ssh`, `sha256sum`, GNU `timeout`, and the runtime libraries
required by the binaries. No compiler or cloud credentials are copied to it.

For coverage-guided fuzzing, also build the instrumented binary:

```sh
go test -c -fuzz=FuzzRecoveryRecord -o <build-dir>/recovery-fuzz ./pkg/recovery
```

Add `--fuzz-binary <build-dir>/recovery-fuzz --fuzz-seconds 30` to the runner.
It runs `FuzzRecoveryRecord` and `FuzzRecoveryEnvelope` separately with two workers.
Both include a valid authenticated record constructed from public test keys and
fixed test-only nonce/timestamp values. The envelope target preserves the valid
outer grant and recomputes the transport hash so mutations reach the envelope
parser. A successful report must include actual fuzz execution counts.

Each run writes private local logs and `report.json` under `test/recovery/artifacts`.
The report records binary hashes, required test repetition counts, elapsed time,
and any primary or cleanup error. Required tests that skip or disappear fail the
run. Logs stop at 16 MiB while commands run. Local timeout/output failures kill
the local command's process group; remote test processes have their own timeouts
and forced-kill deadlines, including if SSH disconnects. Cleanup failures also
make the report fail. Remote directory removal requires its matching run marker.
If Go reports a failing fuzz corpus file, the runner attempts to save that input
locally before cleanup and records any failure to retrieve it.

Run the harness's own tests with:

```sh
python3 -m unittest discover -s test/recovery -p 'test_*.py' -v
```

The crash test verifies 12 records across backup process kills, publisher restarts
during outage, and seed-derived decryption after publisher data deletion. These
records contain branch fixtures. The delegate gate tests exercise real handler
methods with controlled callbacks. These component results do not prove an actual
offline delegated Arkade refresh, mobile restoration, a unilateral exit, disk or
host power-loss durability, or availability beyond a VTXO's expiry.

## Measured deployed-release run

Run `1152ecb375014ec8a31d735f2407eb3b` on September 14, 2026 completed successfully
in 270.566 seconds, including upload and cleanup. Its manifest identifies
Fulmine `e468816350bd38580fc433531fadee9a450e1dfe` and backup
`665b053141c7a1c52d7c64fcab3c36cff42b591d`. Every uploaded binary hash matches
the release manifest; the backup executable is the installed release binary.

- All 27 required component and delegate-gate tests passed five repetitions.
- The crash test recovered 60 acknowledged records across 40 backup process
  kills and 20 publisher restarts, with seed-derived decryption after publisher
  data deletion in each repetition.
- New cases reject another valid same-grant envelope substituted into an outbox,
  whole-outbox copies across intent/batch IDs, missing legacy candidate bindings,
  corrupt saved envelopes and incomplete final pages. Historical exact retries
  after grant expiry and legitimate empty owner snapshots still pass.
- `FuzzRecoveryRecord` reported 18,868 executions; `FuzzRecoveryEnvelope` reported
  8,733. Each target ran for 30 seconds with two workers and a 100 ms minimization
  budget. Both passed.
- All 13 local harness self-tests passed ten repetitions after fixing a process
  cleanup assertion that could race with child-process reaping.

The private artifact directory contains `report.json`, `build-manifest.json`,
per-suite logs and binary hashes. Required tests must pass the specified number
of times; skips do not count. Temporary remote test files were removed.
The separate [live harness](live/README.md) used the same release's Fulmine,
recovery client, recovery tests and backup binary for a real delegated refresh,
seed-only Bitcoin exit, underpriced-package rejection and backup outage. Those
scenarios have their own reports and do not activate automatic wallet delegation.
