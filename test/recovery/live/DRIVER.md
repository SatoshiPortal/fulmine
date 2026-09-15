# Live acceptance adapter contract

The built-in `live` suite executes real Go-SDK delegated refresh and seed-only
exit fixtures. This separate `acceptance` contract additionally requires an
end-user wallet adapter and original-VTXO baseline backup. That adapter is not
implemented, so `acceptance` reports BLOCKED. Supply one with:

```json
{"argv": ["/absolute/path/to/live-adapter"]}
```

An adapter executable is invoked once per action. It reads one JSON request
from stdin and writes one JSON response, with no log chatter. Keep any private
state and diagnostics inside the supplied `workdir`; do not put seeds, keys or
authentication credentials in responses. No shell is involved. The adapter is
trusted test code: the runner checks its evidence, not an independent proof
that the adapter is truthful. Chain checks and process/network controls must
actually be implemented and reviewed in the adapter.

Request:

```json
{"version":1,"run_id":"...","nonce":"...","action":"setup","workdir":"/absolute/fresh/run/driver-state"}
```

Response must echo version, run_id and the request's unpredictable nonce:

```json
{"version":1,"run_id":"...","nonce":"...","status":"ok","evidence":{"chain":"regtest","isolated":true}}
```

Use `status: "blocked"` when a capability is genuinely unavailable, or
`status: "failed"` for a failed operation. Replayed/mismatched responses fail.
The default command timeout is 300 seconds (`--timeout` overrides it).

`capabilities` must return `mode: "live"` and an `actions` list containing all
actions below plus `cleanup`. A simulated or incomplete adapter is blocked
before setup. This action must be read-only and create no resources.
Do not advertise a capability that uses fixture state instead
of performing the action. The runner invokes `cleanup` in a finally block
after setup is attempted. Cleanup must be idempotent and touch only resources
owned by this run, including when setup partially fails.

## Ordered actions and required evidence

All booleans are actual JSON booleans. Counts/amounts are nonnegative integer
numbers, not strings. Txids and public keys use lowercase 64-character hex;
outpoints use `txid:vout`.

| Action | Required evidence / invariant |
|---|---|
| `setup` | `chain="regtest"`, `isolated=true`; start fresh Bitcoin, arkd/indexer, prototype Fulmine and backup instances owned by this run |
| `prepare_wallet` | `nostr_public_key`, `original_outpoint`, `fee_balance_sats=0`, `baseline_backed_up=true`; create a wallet from a test seed, obtain a live VTXO and submit its signed protected delegation |
| `stop_wallet` | `wallet_running=false`; actually stop the client before any delegated renewal |
| `refresh_and_backup` | `replacement_outpoint` different from original, `commitment_txid`, positive `commitment_confirmations`, `ciphertext_sha256`, `wallet_running=false`, `fee_balance_sats=0`; prove durable backup ack precedes forfeit submission using positive ordered `backup_ack_sequence < forfeit_submit_sequence` from instrumentation |
| `stop_ark_and_delegate` | `ark_running=false`, `indexer_running=false`, `delegate_running=false`, `backup_running=true`, `bitcoin_running=true`, `recovery_network_restricted=true`; block recovery's route to all Arkade/delegate endpoints, not merely its preferred URL |
| `erase_wallet` | `wallet_state_removed=true`, `retained_recovery_material=["seed"]`; remove wallet databases/caches and saved transaction material; preserve only the seed plus fixed app configuration |
| `restore_and_fetch` | Original `nostr_public_key`, matching `replacement_outpoint` and `ciphertext_sha256`, `bitcoin_signatures_verified=true`, `owner_authenticated_fetch=true`, `fee_balance_sats=0`, `ark_requests=0`, `delegate_requests=0`; derive identity from seed and import backup in a fresh wallet |
| `fund_exit` | `funding_txid`, positive `funding_confirmations`, positive `funding_sats`, `fee_payer="user"`, `ark_requests=0`, `delegate_requests=0`; deliver new on-chain funding only after restoration |
| `exit_and_sweep` | `sweep_txid`, positive `sweep_confirmations`, positive `received_sats`, `spent_outpoint` matching replacement, `destination_verified_from_seed=true`, `fee_payer="user"`, `ark_requests=0`, `delegate_requests=0`; sign unroll fee transactions and final sweep, mine delays, independently verify outputs via Bitcoin Core |
| `cleanup` | `status="ok"`; stop/remove only the run's containers, processes and temporary secrets |

The runner validates each step before proceeding and writes acceptance
evidence only once every assertion passes. Run-stage order makes late funding
an enforced workflow requirement. The adapter must additionally observe actual
balances, transaction confirmations and network calls instead of returning
hardcoded flags.

## Integration work needed to activate this adapter

1. Adapt the upstream regtest stack to unique Compose project names, ports and
   volumes; its current fixed names are unsuitable for this framework.
2. Drive the existing SDK's delegation preparation with the prototype's signed
   recovery registration and a real offline client lifecycle.
3. Instrument the backup acknowledgement and forfeit-submission boundary so
   their ordering can be asserted across the real delegate's events.
4. Implement import of the decrypted complete candidate bundle into a fresh
   wallet derived from the seed, including chain/off-chain state reconciliation.
5. Connect later on-chain fee funding and the actual unilateral exit/sweep path
   to that restored state, with Arkade and its indexer unreachable.
6. Add live fault scenarios: backup outage before forfeits, crashes around ack,
   stale/missing final record, and expiry during a prolonged outage.

Do not reuse `TestBitcoinLateFunding` to implement the `refresh_and_backup`
action: it is a useful Bitcoin fixture, but it never runs an arkd refresh.
