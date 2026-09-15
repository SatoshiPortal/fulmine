# Encrypted recovery prototype

Branch: `prototype/encrypted-recovery` in `SatoshiPortal/fulmine`.
Companion: `prototype/arkade-recovery` in `SatoshiPortal/BULL-metadata-backup`.

Exact signed bytes, fields and compatibility fixtures are specified in
[the version-1 wire contract](recovery-wire-v1.md).

This experimental delegate extension accepts regtest and Mutinynet only. It
captures a replacement VTXO's signed transaction ancestry during batch
finalization, encrypts the recovery bundle to the user's Nostr public key, and
requires a matching backup receipt before submitting completed forfeits.

Set `FULMINE_RECOVERY_PROTOTYPE_URL` to the backup origin and enable Fulmine's
delegate. Use HTTPS, or loopback HTTP carried over an SSH tunnel. The delegate
info response advertises the backup origin and publisher public key. Each
delegation must include `recovery_registration`: an owner-signed grant, output
metadata and authorization from the actual Ark input owner. Nostr and Ark keys
may differ. Registration is persisted with the delegate task in SQLite or Badger.

The publisher key and immutable encrypted outbox live under
`<FULMINE_DATADIR>/recovery-prototype/`. One process owns that directory. Retain it
across restarts, and use separate data directories for different networks.
Legacy registration sidecars are rejected rather than silently migrated.
Each new outbox carries a publisher signature binding its intent, batch, grant,
plaintext hash and ciphertext hash. This prevents another valid envelope under
the same grant from being substituted during a retry. Outboxes created before
this binding was introduced fail closed on retry and remain untouched for
reconciliation. Already uploaded records can still be fetched and decrypted;
the delegate cannot safely authenticate their plaintext association retroactively
because it does not retain the ephemeral encryption key.
New local outboxes also retain their intent/batch association. Restart scans
verify that association against the filename and existing binding signature,
then verify the historical grant, encrypted event, publisher, origin and byte
count before using a grant ID. Older outboxes lacking the association block new
protected scheduling until reviewed; an authenticated payload alone cannot tell
which hashed filename it belongs to. An exact retry supplied with the original
intent, batch and plaintext can populate these local fields only after verifying
the existing binding. It does not change the saved signed network payload.

## Protected attempt restarts

The same publisher-owned directory also retains `attempt-*.json`. These local
records are publisher-signed and fsynced together with their directory. They bind
the exact commitment PSBT/txid, batch, sorted task IDs and acknowledged ciphertext
hashes. This adds no network message, changes no signed wire bytes and does not
introduce a second task queue.

| Durable observation | Restart behavior |
|---|---|
| Preparing, before upload or while an upload reply is uncertain | Quarantine; preserve candidate and any encrypted outboxes |
| All backup hashes acknowledged | Quarantine; no automatic new round or submission |
| Submission unknown, saved before the forfeit call | Quarantine; never replay that call |
| Submit call returned success, no final event saved | Quarantine; success alone is not batch completion |
| Exact matching final event saved, task DB update interrupted | Replay only the idempotent task completion update |

An old pending task with a matching outbox but no attempt record is quarantined
too: older versions did not persist submission uncertainty. Corrupt attempt
storage or a missing recovery manager prevents protected scheduling. New intents
and `allowReplace` cannot reuse inputs covered by retained attempts or quarantine.
Generic spent-input notifications cannot cancel those attempts and erase the
uncertainty. An exact request retried while a batch is running is rejected without
changing that batch's durable state.

Quarantined tasks appear in the existing failed-task API/UI with a reason prefixed
`protected recovery quarantined:`. For verified attempt records the reason includes
phase, batch and commitment IDs, never PSBTs, user keys or decrypted bundles. To
investigate, stop automatic enrollment for the affected inputs, preserve the task
database and entire recovery directory, and compare the retained exact candidate,
receipt hashes and submitted/finalized observations with independently sufficient
Ark/Bitcoin evidence. Do not delete the marker, reset the task to pending, or submit
the old forfeits as a troubleshooting step. A missing transaction, an unspent
ancestor, an upload receipt or a spent notification alone does not establish a
completed refresh. There is intentionally no automatic release from quarantine.

Later failure or mismatching events cannot quarantine an already recorded final
event, even when its task DB update failed. Stream termination before such a final
event quarantines the last observed phase immediately.

Only a matching final event already durably observed is automatically reconciled;
this is not general reconstruction of an unknown outcome from Ark or Bitcoin.
Attempt records have bounded input sizes, a 10,000-record inspection limit,
32 MiB of cumulative serialized data and 10,000 total task references. New writes
respect these limits, and scans check cancellation between files and task IDs.
They and old outboxes are retained, including completed attempts. Throughput at
that retention limit has not been established. Restoring an older snapshot that
omits both attempt and outbox evidence, losing the publisher directory, or losing
the host is outside the process-restart guarantee: preserve these files and the
task database as one recovery set. Do not independently roll them back.

The targeted restart test kills a child process without closing SQLite/Badger or
the publisher manager at seven boundaries, then reopens both from disk. Its HTTP
ACK fixture and forfeit callback test local ordering and non-replay, not Bitcoin
settlement or backup-host durability. Run:

```sh
go test -race ./pkg/recovery ./internal/core/application -run 'Test(Protected|RetainedOutbox|RecoveryGate|RecoverySubmission|RecoveryDisabled|RecoveryNetwork)' -count=1 -timeout=240s
```

`go build ./cmd/recovery-client` builds the helper for generating test identities,
signing registrations, and fetching/decrypting records with an existing Nostr key.
Fetching resumes through a manifest and verifies previously downloaded files.
The helper does not implement a mobile wallet importer or broadcast exits.

Retries authenticate the saved outbox's grant, ciphertext, ephemeral event and
publisher attestation before making an upload request. Invalid or oversized
saved data fails the gate even if a server would return a matching receipt.
Recovery fetches require every pagination field and must reach the advertised
snapshot before marking a download complete; truncated final pages are errors.
Fetch uses the same HTTPS-or-loopback origin policy as publisher uploads and
rejects invalid origins before signing an owner request.

## Limits and validation

The prototype accepts one ordinary BTC replacement output and at most 16 live
inputs belonging to one Ark owner. Assets, custom contracts and expired inputs
are outside its scope. A bundle is limited to 60 KiB of plaintext. The entire
backup callback has an eight-second deadline. Failed protected tasks require
reconciliation; there is no independent background outbox worker.

Tests cover authorization and encryption, branch validation, candidate-bound
forfeit submission, database restart, publisher ownership, fetch resumption and
lost upload replies. Run:

```sh
go test -race ./pkg/recovery ./internal/core/application ./internal/infrastructure/db/... ./internal/interface/grpc/handlers ./cmd/recovery-client
```

Tests requiring the companion server, Bitcoin Core, or a live Arkade environment
skip unless their fixture configuration is supplied. A skipped test is not
evidence of successful recovery. The regtest Bitcoin fixture exercises later fee
funding and a confirmed CSV sweep.

The isolated live harness has also completed two real arkd/Fulmine refreshes:
the SDK preparation process exits before delegation, the acknowledged candidate
matches the completed task, and acknowledgement precedes forfeit submission.
After stopping Arkade, its indexers and the delegate and erasing wallet state,
a new process derives the Bull recovery Nostr key from the seed, retrieves and
validates the branch, receives fee funding afterward, and confirms the replacement
unroll and CSV sweep on Bitcoin. Each run swept 19,000 sats from a 21,000-sat VTXO.
A separate live backup-process failure scenario checks that no forfeits are
submitted and that Arkade still reports the original VTXO as unspent.

These fixtures use a public test mnemonic on a fresh regtest chain. They do not
establish automatic web/mobile wallet registration, production readiness, or a
Mutinynet end-to-end exit. `TestLiveBullNostrDerivation` checks the BIP85/HKDF
recovery identity against the browser fixture. `TestLivePrepare`,
`TestLiveRestore`, and `TestLiveOriginalUnspent` require the owned live stack.

A stored record is a candidate, not proof that its commitment confirmed or its
VTXO remains unspent. Restoration must check Bitcoin state and expiry. Backups do
not extend expiry, eliminate delegate/operator collusion, or cover every incoming
coin automatically. The user may supply exit fee funds after retrieving a branch;
this extension provides no fee sponsorship.
