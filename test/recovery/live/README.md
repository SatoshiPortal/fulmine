# Recovery test harness

Run from the Fulmine repository. Python 3.10+ standard library, Cargo, and
Go 1.26.5 are required for source builds. The Bitcoin suite additionally needs Docker and the
specified Bitcoin Core image already installed. No image is pulled implicitly.

Clone the companion `SatoshiPortal/BULL-metadata-backup` prototype branch beside
Fulmine, or set `RECOVERY_BACKUP_ROOT` to its absolute checkout path. A sibling
named `backup-server` is also discovered. The Fulmine root is found from this
tracked harness location; `RECOVERY_FULMINE_ROOT` overrides it for detached VM
runners. No particular checkout parent directory is required. Legacy
`prototype/harness` entrypoints are symlinks to these canonical files.

```sh
python3 test/recovery/live/run.py list
python3 test/recovery/live/run.py components
python3 test/recovery/live/run.py bitcoin
python3 test/recovery/live/run.py live --live-binaries /path/to/prebuilt-binaries
python3 test/recovery/live/run.py live --live-backup-outage --live-binaries /path/to/prebuilt-binaries
python3 test/recovery/live/run.py live --live-refresh-count 10 --live-binaries /path/to/prebuilt-binaries
python3 test/recovery/live/run.py acceptance
python3 test/recovery/live/run.py all
python3 -m unittest discover -s test/recovery/live -v
```

## What each suite proves

| Suite | Implementation | Success means |
|---|---|---|
| `components` | Existing Go/Rust integration, unit tests and builds | Signatures, authenticated retrieval, encryption, branch validation, quotas, retries and restart behavior pass their tests |
| `bitcoin` | New Core-backed transaction fixture using the actual Go recovery module and Rust backup process | A captured/retrieved branch can be funded later and swept on Bitcoin after its timelock |
| `live` | Isolated arkd, wallet service, Fulmine delegate, Rust backup, Go SDK and Bitcoin | A real delegated round completes, its acknowledged candidate is retrieved using the Bull-derived Nostr key after Arkade shutdown, and its replacement is funded later and swept |
| `acceptance` | Strict step runner and evidence contract; live wallet/arkd adapter still required | A real delegated refresh survives service loss, seed-only restoration and user-funded exit |
| `all` | Runs `components`, `bitcoin`, and `acceptance` | Full success requires the separate wallet adapter; run `live` explicitly for the built-in delegated-round fixtures |

**The Bitcoin fixture is not a delegated arkd round.** It constructs a small
signed tree transaction and an ordinary Ark CSV exit contract, anchored in a
real regtest commitment transaction. It exercises the real exporter, NIP-44
encryption, Rust HTTP storage, owner-signed retrieval, and Bitcoin submission.
It does not instantiate Fulmine's delegate service or the mobile wallet.

The fixture:

1. Creates an isolated Bitcoin regtest node with a fresh blockchain.
2. Creates a test BIP39 mnemonic and derives fixture keys via BIP86
   `m/86'/1'/0'/0/i`. This is not certification of a wallet's seed format.
3. Anchors a 100,000-sat candidate VTXO with a six-block CSV exit path.
4. Verifies that the user's fee address has zero funds; captures and encrypts
   the signed branch; persists it through the Rust backup server.
5. Drops references to builder state, derives the owner key again from the
   mnemonic and retrieves/decrypts the branch. Fee balance is still zero.
6. Verifies Bitcoin rejects the standalone zero-fee unroll transaction.
7. Supplies 20,000 sats to the user's fee address AFTER retrieval and confirms it.
8. Signs a child spending the anchor plus the user's fee UTXO; submits the
   parent/child package and confirms the unroll. Its fee is 4,000 sats.
9. Verifies a premature final sweep is rejected as `non-BIP68-final`.
10. Mines through the delay and confirms a sweep paying 98,000 sats to another
    address derived from the restored seed. The sweep fee is 2,000 sats.

The test faucet represents Bitcoin the user supplies later. It is not a
production sponsorship feature. Fee amounts are fixture values, not an exit
cost estimate. Only one branch is used; mass exits, deeper trees, fee spikes,
reorgs and batch-expiry races require additional scenarios.

The `live` suite uses nine isolated, pinned containers with an aggregate 2.6GB
memory limit. Run it on an authorized VM, with Docker and its pinned images
already installed. `--live-binaries` accepts `fulmine`, `recovery-client`,
`recovery-tests` (the compiled `pkg/recovery` tests), and
`backup-server`. The live round uses the integrated Rust storage owner behind a
loopback nginx proxy that overwrites `X-Real-IP`; clients send no source identity
header. Without that option, it builds the Go binaries and
builds the Rust backup as well. On the test VM, explicitly install the pinned
images before the first run:

```sh
docker compose -f test/recovery/live/live.compose.json pull
docker pull nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
```

Prebuilt runs need no compiler or companion source checkout on the VM. Copy this
directory and the four binaries, set `RECOVERY_FULMINE_ROOT` to an existing
working directory if the harness is detached, and pass `--live-binaries`.
Include `build-manifest.json` beside the binaries to identify their source:

```json
{"sources":{"fulmine":"<40-character Git revision>","backup":"<40-character Git revision>"},"sha256":{"fulmine":"<sha256>","recovery-client":"<sha256>","recovery-tests":"<sha256>","backup-server":"<sha256>"}}
```

The runner verifies every supplied hash before starting services. Each live
report records the hashes of the copied executables and the supplied revisions.
Without a manifest, prebuilt source revisions are explicitly unknown. Source
builds record checkout revisions and whether their worktrees contain changes.

Bitcoin is premined before starting NBXplorer so another miner cannot race the
fresh-chain check. The delegate must record a completed SQLite task; an outbox
file alone is insufficient. Its final commitment must have a matching backup
acknowledgement before forfeit submission, and seed restoration must retrieve
that exact ciphertext and commitment. Cleanup still removes owned containers
and volumes if collecting their logs fails.

The live fixture deliberately uses the public `abandon … about` BIP39 test
mnemonic on an isolated regtest chain. Its Ark spending key uses the Go SDK's
BIP86 path. Its independent recovery Nostr key uses Bull's BIP85 application
1642/index 0/type 1, followed by the `mnemonic-v1`, `encryption-v1`, and
`nostr-auth-v1` derivations. The authenticated encrypted record is saved as
`restored-record.json` for cross-client decryption tests. This is not yet an
automatic web-wallet registration or refresh test, and it does not make the
separate full-acceptance adapter green.

`--live-backup-outage` kills the actual Rust process before refresh submission.
Success requires a retained candidate, a failed task with no commitment and no
forfeit-submission evidence, plus an independent Arkade indexer query showing
that the original VTXO remains unspent. This scenario does not claim an exit
from the unacknowledged candidate.

`--live-refresh-count` accepts 1 through 10 (default 1). Counts above one cannot
be combined with the outage scenario. The current fixture probes the second
refresh after the first completes and confirms, with the wallet directory and
seed file removed and no mnemonic supplied to the probe. It tests the actual
replacement contract, owner signatures, grant scope, and delegate rejection of
both the original request and a request retargeted to the replacement. It never
repeats the first refresh fixture and counts those repetitions as renewals.

When renewal is unsupported, `offline-renewal-evidence.json` records the requested
count, one completed refresh, the round-two reason, and observed rejections.
The harness still stops Arkade and the delegate before restoring the seed and
exiting the last completed replacement. Its report remains **blocked, exit code
2**, even when that exit succeeds; it does not claim ten offline refreshes.
The tested boundary requires new owner-signed intent/forfeit material and a
new authorized recovery scope. Retaining a delegate leaf alone would not make
the existing input-bound signatures reusable.

## Verified isolated release

Fulmine revision `5c08aa5d4c946d639d9e0937790892690408ab09` and backup revision
`140b236310e62b8bd4bc6ae27b7ff13cc27bb4d8` passed these isolated VM runs on
2026-09-15, using the integrated `backup-server` binary behind nginx:

- `c4d9a8dadb9845b08b7168b8ba14915b`: real delegated refresh, acknowledgement
  before forfeits, Arkade/delegate shutdown, wallet-state deletion, Bull-derived
  Nostr retrieval, later user funding, and a confirmed 19,000-sat sweep from the
  refreshed 21,000-sat VTXO. Bitcoin rejected a correctly signed package offering
  a 1-sat fee with `min relay fee not met, 1 < 277`; both inputs remained unspent.
  After additional user funding, the adequately priced exit succeeded. The
  retained protected-attempt journal was finalized, with the exact acknowledged
  ciphertext receipt and no quarantine reason.
- `269ca1ee129142ab9ddc561e764f0d96`: the real backup process was killed before
  refresh. The candidate was retained, the task failed without forfeits, and
  repeated indexer queries observed the original VTXO unspent for 20 seconds.
  The retained journal remained in `preparing` with an explicit quarantine
  reason; no replacement was claimed complete.

Each report verifies the four executable SHA-256 hashes against the release
manifest. Temporary containers and volumes were removed; the permanent delegate
remained active. The 1-sat rejection proves fee-policy enforcement, not that a
1,000-sat funding UTXO can never cover an exit. These results do not establish
automatic browser/mobile registration, recovery after expiry, reorg handling,
or a Mutinynet exit.

## Reports and truthful failures

Every run gets a fresh `test/recovery/live/artifacts/<run-id>/` directory containing:

- `report.json`: case status and an explicit `full_acceptance` status.
- `junit.xml`: CI-compatible results; blocked cases are marked skipped.
- Per-command bounded logs, plus public regtest transaction evidence from the
  Bitcoin test (`bitcoin-evidence.json`). Live runs retain private fixture
  state, including the public test seed and isolated service wallet data; do
  not publish the artifact directory wholesale.

Exit codes: **0 passed**, **1 failed**, **2 blocked**. `all` and `acceptance`
currently return 2 unless a real adapter is supplied. CI must use the process
exit code as well as JUnit: skipped/blocked acceptance is not success.
Required Go tests must actually run and pass; a filtered-out or skipped test
does not count. Commands have timeouts and output bounds. Logs are in private
run directories and may contain public regtest transaction/wallet metadata.

```sh
python3 test/recovery/live/run.py all --output /tmp/recovery-results
python3 test/recovery/live/run.py acceptance --driver /path/to/live-driver.json
```

There is no fake acceptance driver enabled by default. The synthetic evidence
in `test_harness.py` tests assertion failures only. The live adapter contract
and unfinished integration tasks are in [DRIVER.md](DRIVER.md).

## Isolation and cleanup

The Bitcoin suite uses a unique container name and ownership label, a tmpfs
datadir, no P2P connections and a random loopback-only RPC port. It never invokes
the upstream fixed-name regtest scripts, uses existing wallet data, or removes
other containers. Cleanup verifies the run's ownership label before removing
its container, including on test failure or interruption. Inherited Bitcoin RPC
environment variables are cleared before starting tests. The Go fixture also
refuses a non-regtest or non-empty blockchain.

The default image is Bitcoin Core 30.0, pinned to the locally verified digest:

```
bitcoin/bitcoin@sha256:68b927b6a2d3b019ce7655f3fd0eb9a4c7011310886ebc7890e5246c16df5ec6
```

Use `--bitcoin-image IMAGE` for an already installed compatible alternative.
The selected image ID is recorded in the run logs. A Docker daemon failure or
a forcibly killed harness may prevent cleanup; any surviving test container
has the `bull.recovery.run=<run-id>` label. Never use a blanket Docker prune.

## Failure coverage

| Failure | Current test |
|---|---|
| Bare public key or publisher tries to fetch | Go/Rust HTTP integration |
| Wrong decryption key or corrupted encrypted record | Go crypto tests |
| Expired append grant, changed grant, quota exceeded | Rust tests |
| Upload returns HTTP 503; delegate manager is reconstructed | Go durable-outbox restart tests |
| Backup commits an upload but its response is lost | `TestCommittedUploadLostResponse` against real Rust, including publisher restart and exact retry |
| Invalid/missing branch signature, wrong amount | Go exporter tests |
| New uploads arrive during pagination | Go/Rust HTTP integration |
| No fee UTXO at capture or retrieval | Core-backed Bitcoin fixture |
| Sweep before CSV maturity | Core-backed Bitcoin rejection |
| Signed exit package offers too little fee | Live Core rejects a 1-sat package; inputs remain unspent, then adequate fees allow a confirmed exit |
| Adapter uses old VTXO, online wallet, early funding, wrong destination or sponsor | Harness acceptance assertions and mutation tests |
| Real backup outage before Fulmine forfeits | Live backup-process kill, failed task without forfeits, original unspent across a 20-second observation |
| Actual seed-only wallet import with Arkade unreachable | Still requires the live wallet adapter |
| Expired/swept ancestor, reorg, fee exhaustion, interrupted unroll | Additional Bitcoin/live scenarios required |
