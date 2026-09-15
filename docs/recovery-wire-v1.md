# Delegated recovery wire contract, version 1

This document freezes the existing experimental protocol. It does not authorize
mainnet, integrate recovery into the normal metadata API, or promise indefinite
offline recovery. The signed domain remains exactly
`bullbitcoin-arkade-recovery-prototype-v1`; removing `prototype` changes every
signature. The companion document is referenced from BULL-metadata-backup's
`RECOVERY_PROTOTYPE.md`.

## Identities

| Identity | Authority |
|---|---|
| User Nostr key | Signs grants and fetches; receives NIP-44 encryption |
| User Ark spending key | Authorizes the grant for the actual delegated inputs; signs the eventual exit |
| Delegate publisher key | Signs uploads, envelope attestations and local outbox bindings; cannot decrypt records |
| Ephemeral NIP-44 sender key | Encrypts one bundle to the user's Nostr public key and signs its Nostr event; discarded after sealing |
| Bull server-auth key | Separate whole-wallet backup identity; not this resource's encryption recipient or fetch identity |

All wire public keys are lowercase 32-byte x-only secp256k1 hex. Signatures are
lowercase 64-byte BIP340 Schnorr hex, verified over a 32-byte digest. There is no
lookup token. An owner-signed grant authorizes one publisher, origin and scope;
the delegate also requires authorization by each actual Ark input owner.

Bull credentials use BIP32 `m/83696968'/1642'/0'/1'`, then BIP85 HMAC-SHA512 with
key `bip-entropy-from-k`, retaining all 64 output bytes. HKDF-SHA256 uses salt
`bullbitcoin-backup-password`, info `mnemonic-v1`, length 16, for twelve English
BIP39 backup words. Their entropy feeds HKDF with the same salt, info
`encryption-v1`, length 32. HMAC-SHA256 keyed by that root over
`nostr-auth-v1 || 00 || counter` produces the Nostr scalar; use the first valid
nonzero scalar with a one-byte counter starting at zero. Server authentication
uses `server-auth-v1` instead. The public mobile vector comes from Bull Mobile
`distributed-resiliant-backups` commit `b25567a96`.

This is separate from the existing web wallet's spending derivation in
`src/lib/wallet.ts`: `m/44/1237/0'/0/0` (the first two components are not hardened).
Neither backup words nor this protocol replace the spending key. The fixture's
Ark key is deliberately synthetic and is not a wallet spending-derivation vector.

## Signed bytes

Define `D(a, b, ...) = SHA256(UTF8(a) || 00 || UTF8(b) || ...)`, with one NUL
separator and no trailing separator. Integers below are unsigned canonical base
10 with no padding. Hashes are lowercase 32-byte hex, not raw hash bytes, when
used as fields inside another digest. Origin is the exact configured origin;
signatures do not normalize it. Clients permit HTTPS or prototype loopback HTTP
without credentials, path, query or fragment. Bind deployment origins before
creating grants; changing an SSH-facing or browser-facing origin breaks grants.

Let `DOMAIN` be the exact domain above:

| Digest | Ordered fields supplied to D |
|---|---|
| Grant | DOMAIN, `grant`, owner, publisher, origin, id, scope, valid_from, expires_at, max_records, max_bytes |
| Store | DOMAIN, `store`, hex(grant digest), ciphertext_sha256, ciphertext_bytes, timestamp |
| Fetch | DOMAIN, `fetch`, owner, after, snapshot, timestamp |
| Intent scope | DOMAIN, `scope`, canonical intent message string, canonical intent proof PSBT string, compact JSON output-metadata array |
| Publisher attestation | DOMAIN, `sealed`, owner, hex(grant digest), event.id |
| Local outbox binding | DOMAIN, `outbox-binding-v1`, intent ID, batch ID, hex(grant digest), plaintext hash, ciphertext hash |

The grant signature is made by the user Nostr key. The store signature and
attestation use the publisher key; the fetch signature uses the user Nostr key.
Ark owner authorization signs the grant digest with the separate spending key.
Output metadata serializes in Go field order: `script`, `tapscripts`, `key_path`.
Go JSON encoding escapes `<`, `>`, `&`, U+2028 and U+2029 inside that array.
The scope_encoding fixture freezes these bytes; ordinary JSON.stringify is not
equivalent without those escapes. The message and proof are literal digest
fields, not JSON-reencoded strings. Preserve these bytes when constructing the
scope. Signatures themselves are not
included in the grant digest.

## HTTP resource and pagination

The current executable is a separate loopback-only prototype resource:

- `POST /api/v1/arkade-recovery-records`: JSON store request; successful receipt
  is `{ "id": positive integer, "ciphertext_sha256": hash }` after SQLite commit.
- `POST /api/v1/arkade-recovery-records/fetch`: JSON signed fetch request;
  response is `{ "records": [...], "snapshot": integer, "next_after": integer|null }`.

Grant fields are the grant digest fields after `grant`, plus `signature`.
Store fields are `grant`, `ciphertext`, `ciphertext_sha256`, `ciphertext_bytes`,
`timestamp`, `signature`. Fetch fields are `owner`, `after`, `snapshot`,
`timestamp`, `signature`. Each returned record has `id`, `grant`, `ciphertext`,
`ciphertext_sha256`. The common fixture includes exact field-name lists.

Start with `after=0,snapshot=0`. The server pins the owner's highest record ID,
returns at most eight records in increasing ID order and sets `next_after` to
the last returned ID only if more records remain in that snapshot. IDs are
allocated globally: gaps within one owner's history are normal. Subsequent
requests sign the returned snapshot and cursor. Missing retained cursor or
snapshot rows cause conflict, even when newer records exist. A valid final page
reaches the advertised snapshot; an empty owner has snapshot zero. All three
response fields must exist, and records must be an array, not null. Completion
must not be inferred from a transport error or an omitted field.

These cursors are not an authenticated history commitment. They cannot prove
that a fresh seed-only recovery saw all prior records, detect every deleted
interior row, or prove that candidates remain unspent. The metadata server has
no user private key and cannot perform a unilateral exit.

Exact retries identify `(owner, grant.id, ciphertext hash)`. A previously stored
record can be acknowledged after grant expiry only with a fresh signed upload
request and matching persisted bytes/grant. New appends require a currently
valid grant. Restoring a database behind an expired grant can therefore strand
normal re-upload of its lost records; this needs a separate operational recovery
procedure, not weakened append authorization. Retries do not consume quota twice.

## Envelope and bundle

`ciphertext` is canonical padded standard base64 of UTF-8 JSON:
`{ "event": EVENT, "publisher_signature": SIGNATURE }`. The decoded JSON's SHA256
is `ciphertext_sha256`; its byte length is `ciphertext_bytes`. EVENT has exactly
`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`. Its ID is SHA256 of
compact UTF-8 JSON `[0,pubkey,created_at,kind,tags,content]`, as in NIP-01.
`kind=30078`; tags are exactly `[["p",owner],["d",grant.id]]` in that order.
`pubkey` is the ephemeral sender; `content` is NIP-44 v2 encryption to the Nostr
owner, and `sig` authenticates the event ID. The publisher attestation binds the
event ID to the owner and grant. Receivers verify every signature and binding
before decryption. The Rust storage resource verifies the grant/upload and
opaque bytes; envelope inspection in its conformance test is not runtime
validation of the hidden bundle.

The decrypted version-1 bundle contains these fields:

| Field | Encoding and meaning |
|---|---|
| `version` | Integer 1 |
| `network` | `regtest` or `mutinynet` in the protected prototype |
| `batch_id` | Ark batch identifier |
| `commitment_psbt`, `commitment_txid` | Base64 PSBT and lowercase displayed transaction ID |
| `registration` | `grant`, `outputs`, `owner_signatures` map from Ark owner x-only key to signature |
| `intent` | Existing fields **`Message`, `Proof`, `Txid`, `Inputs`**, including their capitalization |
| `replacement_outpoint` | Displayed transaction ID followed by `:` and decimal output index |
| `branch_psbts` | Base64 PSBT ancestry, parent first |
| `batch_sweep_script` | Hex operator sweep tapscript, retaining its expiry units and value |

Each `outputs` element contains hex `script`, hex-script array `tapscripts`, and
string `key_path`. Intent `Inputs` currently serialize as objects with **`Hash`**
(a 32-element byte array in the library's internal hash order) and **`Index`**
(an integer). They are not `txid:vout` strings. A future transport-type extraction
must preserve this existing JSON shape or introduce an explicit migration.

Bundle version does not version the HTTP request by itself. Envelope readers
authenticate/decrypt bytes; they do not establish supported bundle version,
Bitcoin validity, confirmation, spend history or remaining expiry. Importers
must reject unsupported versions and contracts before treating them as usable
exit candidates. The golden application test freezes the current serialized
bundle and verifies its synthetic signed ancestry; it is not an Ark acceptance
or funded-exit test.

## Bounds and lifecycle

| Bound | Current value |
|---|---|
| Grant duration | At most 32 days, valid_from/expires_at inclusive |
| Upload/fetch timestamp tolerance | Absolute difference from server clock at most 300 seconds |
| Per-grant append quota | 1–16 records, 1–2 MiB decoded envelope bytes |
| One record | At most 128 KiB decoded envelope; delegate plaintext at most 60 KiB |
| Owner storage | 16 MiB decoded envelope bytes |
| Global prototype storage | 256 MiB decoded envelope bytes and 10,000 records |
| HTTP bodies | Store 192 KiB; fetch 4 KiB |
| Fetch page | Eight records; cursors fit signed SQLite i64 |
| Go response/read limits | HTTP response 2 MiB; saved fetch history 10,000 records |
| Delegate scope | One ordinary BTC output, one Ark owner, at most 16 live inputs |
| Delegate registration | At most 16 KiB |
| Backup callback | One eight-second budget for all selected tasks, currently serialized |

Protocol integers are Go/Rust u64 where declared; record IDs use positive i64.
JavaScript implementations must reject unsafe numeric representations rather
than round signed fields. Cross-language common fixtures use exactly represented
integers. Current quota numbers are prototype capacity bounds, not retention
promises or an acceptable production outage budget.

The delegate seals a candidate, fsyncs its immutable outbox, obtains a matching
backup receipt, persists the acknowledged request, then permits its completed
forfeits to be submitted for that candidate only. A lost submission response is
uncertain; do not equate it with failure or submit it repeatedly. Batch handler
attempt state is not yet a durable cross-process reconciliation system.

Local outboxes additionally bind the candidate and plaintext/ciphertext hashes
with a publisher signature. Legacy unsigned outboxes are retained unchanged but
fail closed on retry; the delegate cannot safely retroactively prove their
plaintext association after discarding the ephemeral key. Historical uploaded
records remain readable after grant expiry. No record may be deleted merely
because a newer candidate exists or its append grant expired. Backups do not
extend Bitcoin expiry, provide fee sponsorship, or cover every incoming coin.

## Golden conformance checks

Canonical fixture: `test/recovery/fixtures/recovery-wire-v1.json` in Fulmine.
Companion copy: `tests/fixtures/recovery-wire-v1.json` in BULL-metadata-backup.
Both have SHA256
`4ce1053bb849e7bc0db7cd3702c1f623dcea5d60e45853ac1b5c4e0c224092c8`.
The public test-only keys, fixed NIP-44 nonce and historical timestamps make
regeneration deterministic. Never fund these keys. The mobile seed vector is
32 bytes of `0x63`; it is not a BIP39 wallet mnemonic.

From Fulmine:

```sh
go test -race ./pkg/recovery ./internal/core/application -run '^TestRecovery(Wire|BundleWire)Conformance$' -count=1
go run ./test/recovery/fixtures/generate.go
git diff --exit-code -- test/recovery/fixtures/recovery-wire-v1.json
python3 test/recovery/check-fixture-copies.py ../backup-server/tests/fixtures/recovery-wire-v1.json ../wallet/src/test/fixtures/recovery-wire-v1.json
```

From BULL-metadata-backup:

```sh
cargo test --locked --bin arkade-recovery-prototype shared_wire_conformance_vector
```

These checks are offline and use synthetic keys/in-memory SQLite. Missing
fixtures fail; they are not skipped. A deliberate fixture change requires
reviewing the contract and updating the copies and pinned hashes together.
Historical records must keep decrypting; regeneration is not a migration.
