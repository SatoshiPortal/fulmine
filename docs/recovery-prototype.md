# Encrypted recovery prototype

Branch: `prototype/encrypted-recovery` in `SatoshiPortal/fulmine`.
Companion: `prototype/arkade-recovery` in `SatoshiPortal/BULL-metadata-backup`.

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
