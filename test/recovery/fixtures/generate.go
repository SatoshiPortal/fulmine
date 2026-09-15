//go:build ignore

// Regenerates public test material only. Never fund any of these keys or outputs.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"

	"github.com/ArkLabsHQ/fulmine/internal/core/domain"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nbd-wtf/go-nostr/nip44"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
func key(n byte) *btcec.PrivateKey { k, _ := btcec.PrivKeyFromBytes([]byte{n}); return k }
func encode(v any) []byte          { return must(json.Marshal(v)) }
func fields(value any) []string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encode(value), &object); err != nil {
		panic(err)
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func main() {
	root := must(hex.DecodeString("301375cfd80649921db2be0ad3bb812460bf9a712a256de81704f909f84907f3"))
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte("nostr-auth-v1\x00\x00"))
	owner, _ := btcec.PrivKeyFromBytes(mac.Sum(nil))
	publisher, ephemeral, ark, server := key(42), key(43), key(44), key(45)
	contract := script.NewDefaultVtxoScript(ark.PubKey(), server.PubKey(), arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 6})
	outputKey, _, err := contract.TapTree()
	if err != nil {
		panic(err)
	}
	outputScript := must(txscript.PayToTaprootScript(outputKey))
	tapscripts := must(contract.Encode())
	rootScript := must(txscript.PayToTaprootScript(ephemeral.PubKey()))
	commitTx := wire.NewMsgTx(3)
	commitTx.AddTxIn(&wire.TxIn{})
	commitTx.AddTxOut(wire.NewTxOut(10000, rootScript))
	commit := must(psbt.NewFromUnsignedTx(commitTx))
	commitPSBT := must(commit.B64Encode())
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: commitTx.TxHash(), Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(wire.NewTxOut(10000, outputScript))
	packet := must(psbt.NewFromUnsignedTx(tx))
	prev := txscript.NewCannedPrevOutputFetcher(rootScript, 10000)
	sighash := must(txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(tx, prev), txscript.SigHashDefault, tx, 0, prev))
	packet.Inputs[0].TaprootKeySpendSig = must(schnorr.Sign(ephemeral, sighash)).Serialize()
	branch, outpoint, err := recovery.ExtractBranch(&tree.TxTree{Root: packet}, commit, outputScript, 10000)
	if err != nil {
		panic(err)
	}
	outputs := []recovery.Output{{Script: hex.EncodeToString(outputScript), Tapscripts: tapscripts, KeyPath: "m/0/0"}}
	intent := domain.Intent{Message: `{"type":"register","fixture":"schema-only"}`, Proof: commitPSBT, Txid: recovery.Hash([]byte("synthetic-intent")), Inputs: []wire.OutPoint{{Hash: commitTx.TxHash(), Index: 0}}}
	grant := recovery.Grant{Owner: recovery.Public(owner), Publisher: recovery.Public(publisher), Origin: "http://127.0.0.1:9081", ID: recovery.Hash([]byte("recovery-wire-v1-grant")), Scope: recovery.Scope(intent.Message, intent.Proof, outputs), ValidFrom: 90, ExpiresAt: 110, MaxRecords: 16, MaxBytes: 2097152}
	grant.Signature = must(recovery.Sign(owner, grant.Digest()))
	registration := recovery.Registration{Grant: grant, Outputs: outputs, OwnerSignatures: map[string]string{recovery.Public(ark): must(recovery.Sign(ark, grant.Digest()))}}
	sweep := script.CSVMultisigClosure{MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{server.PubKey()}}, Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 60}}
	bundle := struct {
		Version          int                   `json:"version"`
		Network          string                `json:"network"`
		BatchID          string                `json:"batch_id"`
		Commitment       string                `json:"commitment_psbt"`
		CommitmentTxID   string                `json:"commitment_txid"`
		Registration     recovery.Registration `json:"registration"`
		Intent           domain.Intent         `json:"intent"`
		Replacement      string                `json:"replacement_outpoint"`
		Branch           []string              `json:"branch_psbts"`
		BatchSweepScript string                `json:"batch_sweep_script"`
	}{1, "regtest", "golden-batch-v1", commitPSBT, commitTx.TxID(), registration, intent, outpoint, branch, hex.EncodeToString(must(sweep.Script()))}
	plain := encode(bundle)
	conversation := must(nip44.GenerateConversationKey(grant.Owner, hex.EncodeToString(ephemeral.Serialize())))
	content := must(nip44.Encrypt(string(plain), conversation, nip44.WithCustomNonce(bytes.Repeat([]byte{7}, 32))))
	event := recovery.Event{PubKey: recovery.Public(ephemeral), CreatedAt: 100, Kind: 30078, Tags: [][]string{{"p", grant.Owner}, {"d", grant.ID}}, Content: content}
	eventDigest := sha256.Sum256(encode([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content}))
	event.ID = hex.EncodeToString(eventDigest[:])
	event.Sig = must(recovery.Sign(ephemeral, eventDigest[:]))
	attestation := recovery.Digest(recovery.Domain, "sealed", grant.Owner, hex.EncodeToString(grant.Digest()), event.ID)
	envelope := recovery.Envelope{Event: event, PublisherSignature: must(recovery.Sign(publisher, attestation))}
	raw := encode(envelope)
	store := recovery.StoreRequest{Grant: grant, Ciphertext: base64.StdEncoding.EncodeToString(raw), Hash: recovery.Hash(raw), Bytes: uint64(len(raw)), Timestamp: 100}
	store.Signature = must(recovery.Sign(publisher, store.Digest()))
	fetch := recovery.FetchRequest{Owner: grant.Owner, After: 0, Snapshot: 0, Timestamp: 100}
	fetch.Signature = must(recovery.Sign(owner, fetch.Digest()))
	record := recovery.Record{ID: 1, Grant: grant, Ciphertext: store.Ciphertext, Hash: store.Hash}
	scopeOutputs := []recovery.Output{{Script: outputs[0].Script, Tapscripts: outputs[0].Tapscripts, KeyPath: "m/0/<>&\u2028\u2029"}}
	scopeMessage, scopeProof := "message<&>\u2028\u2029", "proof<&>\u2028\u2029"
	fixture := map[string]any{
		"fixture_version": 1, "domain": recovery.Domain,
		"scope_encoding":   map[string]any{"message": scopeMessage, "proof": scopeProof, "outputs": scopeOutputs, "outputs_json": string(encode(scopeOutputs)), "digest": recovery.Scope(scopeMessage, scopeProof, scopeOutputs)},
		"schema_fields":    map[string][]string{"grant": fields(grant), "store": fields(store), "fetch": fields(fetch), "record": fields(record), "envelope": fields(envelope), "event": fields(event), "bundle": fields(bundle), "registration": fields(registration), "output": fields(outputs[0]), "intent": fields(intent), "intent_input": fields(intent.Inputs[0])},
		"provenance":       map[string]any{"generator": "test/recovery/fixtures/generate.go", "warning": "Public synthetic keys only. Never fund. Signature-valid ancestry with an unfunded synthetic commitment, not a complete Ark round or a valid enrollment intent.", "mobile_vector_commit": "b25567a96", "nonce_hex": hex.EncodeToString(bytes.Repeat([]byte{7}, 32))},
		"identity":         map[string]any{"bip85_seed_hex": hex.EncodeToString(bytes.Repeat([]byte{99}, 32)), "bip85_path": "m/83696968'/1642'/0'/1'", "backup_words": "abandon differ wave love claim impact beach put bunker polar fragile crop", "encryption_root_hex": hex.EncodeToString(root), "nostr_public_key": grant.Owner, "server_auth_public_key": "469a4d1d8ddc1a69886f3f729a02c58b203695627a90a0cf9a3dfda562292ceb"},
		"public_test_keys": map[string]string{"nostr_private_key": hex.EncodeToString(owner.Serialize()), "publisher_private_key": hex.EncodeToString(publisher.Serialize()), "ephemeral_private_key": hex.EncodeToString(ephemeral.Serialize()), "ark_private_key": hex.EncodeToString(ark.Serialize())},
		"grant":            grant, "store": store, "fetch": fetch, "record": record, "envelope": envelope, "bundle": bundle, "bundle_json": string(plain),
		"digests": map[string]string{"grant": hex.EncodeToString(grant.Digest()), "store": hex.EncodeToString(store.Digest()), "fetch": hex.EncodeToString(fetch.Digest()), "scope": grant.Scope, "event": event.ID, "attestation": hex.EncodeToString(attestation), "ciphertext": store.Hash, "plaintext": recovery.Hash(plain)},
	}
	if !bytes.Equal(must(recovery.Open(record, owner)), plain) {
		panic("fixture did not decrypt")
	}
	out := must(json.MarshalIndent(fixture, "", "  "))
	out = append(out, '\n')
	if err := os.WriteFile("test/recovery/fixtures/recovery-wire-v1.json", out, 0644); err != nil {
		panic(err)
	}
}
