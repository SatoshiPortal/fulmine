package recovery

// This is a Bitcoin-backed fixture test, NOT a delegated arkd round. The harness
// gives it a fresh, private Bitcoin Core regtest node. It proves that recorded
// branches can be retrieved before the user supplies fee funding, then unrolled
// and swept under actual Bitcoin consensus/mempool rules.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

type bitcoinRPC struct {
	url    string
	client *http.Client
}

func (r bitcoinRPC) call(method string, params any, result any) error {
	raw, err := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": "recovery-harness", "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, r.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(os.Getenv("RECOVERY_BITCOIN_RPC_USER"), os.Getenv("RECOVERY_BITCOIN_RPC_PASSWORD"))
	response, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err = json.Unmarshal(body, &reply); err != nil {
		return err
	}
	if reply.Error != nil {
		return fmt.Errorf("Bitcoin RPC %s: %d %s", method, reply.Error.Code, reply.Error.Message)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Bitcoin RPC HTTP %d", response.StatusCode)
	}
	if result != nil {
		return json.Unmarshal(reply.Result, result)
	}
	return nil
}
func (r bitcoinRPC) must(t *testing.T, method string, params any, result any) {
	t.Helper()
	require.NoError(t, r.call(method, params, result))
}
func txHex(t *testing.T, tx *wire.MsgTx) string {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, tx.Serialize(&b))
	return hex.EncodeToString(b.Bytes())
}
func decodeTx(t *testing.T, raw string) *wire.MsgTx {
	t.Helper()
	b, err := hex.DecodeString(raw)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	require.NoError(t, tx.Deserialize(bytes.NewReader(b)))
	return tx
}
func addressFor(t *testing.T, key *btcec.PublicKey) string {
	t.Helper()
	a, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(key), &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	return a.EncodeAddress()
}
func fixtureSeedKey(t *testing.T, mnemonic string, index uint32) *btcec.PrivateKey {
	t.Helper()
	seed := bip39.NewSeed(mnemonic, "")
	defer clear(seed)
	key, err := bip32.NewMasterKey(seed)
	require.NoError(t, err)
	for _, child := range []uint32{0x80000056, 0x80000001, 0x80000000, 0, index} {
		key, err = key.NewChildKey(child)
		require.NoError(t, err)
	}
	private, _ := btcec.PrivKeyFromBytes(key.Key)
	return private
}

func startFixtureBackup(t *testing.T) (*Manager, string) {
	t.Helper()
	binary := os.Getenv("BACKUP_PROTOTYPE_BIN")
	require.NotEmpty(t, binary)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	origin := "http://" + addr
	manager, err := NewManager(filepath.Join(t.TempDir(), "delegate"), origin)
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })
	cmd := exec.Command(binary, filepath.Join(t.TempDir(), "backup.sqlite"), addr, origin, manager.Public())
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)
	return manager, origin
}

func TestBitcoinLateFunding(t *testing.T) {
	endpoint := os.Getenv("RECOVERY_BITCOIN_RPC_URL")
	if endpoint == "" {
		t.Skip("run through harness/run.py bitcoin to get an isolated node")
	}
	rpc := bitcoinRPC{url: endpoint, client: &http.Client{Timeout: 10 * time.Second}}
	var chain struct {
		Chain  string `json:"chain"`
		Blocks int    `json:"blocks"`
	}
	rpc.must(t, "getblockchaininfo", []any{}, &chain)
	require.Equal(t, "regtest", chain.Chain, "refuse non-regtest")
	require.Zero(t, chain.Blocks, "refuse a previously used Bitcoin node")
	rpc.must(t, "createwallet", []any{"faucet"}, nil)
	faucet := rpc
	faucet.url = endpoint + "/wallet/faucet"
	var miningAddress string
	faucet.must(t, "getnewaddress", []any{}, &miningAddress)
	mine := func(n int) { t.Helper(); rpc.must(t, "generatetoaddress", []any{n, miningAddress}, nil) }
	mine(101)

	// New test mnemonic, never printed or included in report artifacts. This is
	// a fixture BIP86 derivation, not the mobile wallet's restoration integration.
	entropy, err := bip39.NewEntropy(128)
	require.NoError(t, err)
	mnemonic, err := bip39.NewMnemonic(entropy)
	clear(entropy)
	require.NoError(t, err)
	user := fixtureSeedKey(t, mnemonic, 0)
	feeKey := txscript.ComputeTaprootKeyNoScript(user.PubKey())
	feeAddress := addressFor(t, feeKey)
	feeScript, err := txscript.PayToTaprootScript(feeKey)
	require.NoError(t, err)
	scanFee := func() float64 {
		t.Helper()
		var scan struct {
			Total float64 `json:"total_amount"`
		}
		rpc.must(t, "scantxoutset", []any{"start", []string{"addr(" + feeAddress + ")"}}, &scan)
		return scan.Total
	}
	require.Zero(t, scanFee(), "no exit fee funding exists before branch creation")

	rootKey, serverKey := testKey(t), testKey(t)
	rootAddress := addressFor(t, rootKey.PubKey())
	rootScript, err := txscript.PayToTaprootScript(rootKey.PubKey())
	require.NoError(t, err)
	const amount int64 = 100000
	var unsignedCommit string
	faucet.must(t, "createrawtransaction", []any{[]any{}, []any{map[string]any{rootAddress: 0.001}}}, &unsignedCommit)
	var funded struct {
		Hex string `json:"hex"`
	}
	faucet.must(t, "fundrawtransaction", []any{unsignedCommit, map[string]any{"changePosition": 1}}, &funded)
	var signedCommit struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	faucet.must(t, "signrawtransactionwithwallet", []any{funded.Hex}, &signedCommit)
	require.True(t, signedCommit.Complete)
	rpc.must(t, "sendrawtransaction", []any{signedCommit.Hex}, nil)
	mine(1)
	commitTx := decodeTx(t, signedCommit.Hex)
	require.Equal(t, rootScript, commitTx.TxOut[0].PkScript)
	commitUnsigned := commitTx.Copy()
	for _, in := range commitUnsigned.TxIn {
		in.Witness = nil
		in.SignatureScript = nil
	}
	commit, err := psbt.NewFromUnsignedTx(commitUnsigned)
	require.NoError(t, err)

	lock := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 6}
	contract := script.NewDefaultVtxoScript(user.PubKey(), serverKey.PubKey(), lock)
	outputKey, tapTree, err := contract.TapTree()
	require.NoError(t, err)
	outputScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	exitLeaf, err := contract.ExitClosures()[0].Script()
	require.NoError(t, err)
	merkle, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(exitLeaf).TapHash())
	require.NoError(t, err)
	anchor := []byte{0x51, 0x02, 0x4e, 0x73}
	parent := wire.NewMsgTx(3)
	parent.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: commitTx.TxHash(), Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	parent.AddTxOut(wire.NewTxOut(amount, outputScript))
	parent.AddTxOut(wire.NewTxOut(0, anchor))
	prev := txscript.NewCannedPrevOutputFetcher(rootScript, amount)
	digest, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(parent, prev), txscript.SigHashDefault, parent, 0, prev)
	require.NoError(t, err)
	sig, err := schnorr.Sign(rootKey, digest)
	require.NoError(t, err)
	packet, err := psbt.NewFromUnsignedTx(parent)
	require.NoError(t, err)
	packet.Inputs[0].TaprootKeySpendSig = sig.Serialize()
	branch, replacement, err := ExtractBranch(&tree.TxTree{Root: packet}, commit, outputScript, amount)
	require.NoError(t, err)
	commitPSBT, err := commit.B64Encode()
	require.NoError(t, err)
	type capsule struct {
		Branch       []string
		Commitment   string
		Replacement  string
		Script       []byte
		ExitLeaf     []byte
		ControlBlock []byte
		Amount       int64
	}
	payload, err := json.Marshal(capsule{branch, commitPSBT, replacement, outputScript, exitLeaf, merkle.ControlBlock, amount})
	require.NoError(t, err)
	manager, origin := startFixtureBackup(t)
	grant := testGrant(t, user, manager.Public(), origin)
	require.NoError(t, manager.Deliver(context.Background(), "bitcoin-fixture", commitTx.TxID(), Registration{Grant: grant}, payload))
	require.Zero(t, scanFee(), "branch was backed up without fee funding")
	var captureHeight int
	rpc.must(t, "getblockcount", []any{}, &captureHeight)
	// Drop access to the builder's signing keys/data. Recovery below uses only
	// the mnemonic, backup response and Bitcoin. No Ark client/indexer is started.
	rootKey.Zero()
	serverKey.Zero()
	user.Zero()
	clear(payload)
	packet = nil
	branch = nil
	commit = nil
	parent = nil
	require.NoError(t, manager.Close())
	manager = nil
	user = fixtureSeedKey(t, mnemonic, 0)
	defer user.Zero()
	page, err := FetchPage(context.Background(), origin, user, 0, 0)
	require.NoError(t, err)
	require.Len(t, page.Records, 1)
	plaintext, err := Open(page.Records[0], user)
	require.NoError(t, err)
	var restored capsule
	require.NoError(t, json.Unmarshal(plaintext, &restored))
	clear(plaintext)
	require.Equal(t, replacement, restored.Replacement)
	require.Zero(t, scanFee(), "no fees supplied before retrieval")
	restoredCommit, err := psbt.NewFromRawBytes(strings.NewReader(restored.Commitment), true)
	require.NoError(t, err)
	restoredPacket, err := psbt.NewFromRawBytes(strings.NewReader(restored.Branch[0]), true)
	require.NoError(t, err)
	_, _, err = ExtractBranch(&tree.TxTree{Root: restoredPacket}, restoredCommit, restored.Script, restored.Amount)
	require.NoError(t, err)
	restoredParent := restoredPacket.UnsignedTx.Copy()
	restoredParent.TxIn[0].Witness = wire.TxWitness{restoredPacket.Inputs[0].TaprootKeySpendSig}
	var accepted []struct {
		Allowed bool `json:"allowed"`
	}
	rpc.must(t, "testmempoolaccept", []any{[]string{txHex(t, restoredParent)}}, &accepted)
	require.Len(t, accepted, 1)
	require.False(t, accepted[0].Allowed, "unfunded zero-fee parent must not pass")

	// The user supplies confirmed Bitcoin AFTER fetching the backup.
	var fundingID string
	faucet.must(t, "sendtoaddress", []any{feeAddress, 0.0002}, &fundingID)
	mine(1)
	require.InDelta(t, 0.0002, scanFee(), 0.000000001)
	var fundingRaw string
	rpc.must(t, "getrawtransaction", []any{fundingID}, &fundingRaw)
	funding := decodeTx(t, fundingRaw)
	fundingIndex := -1
	for i, out := range funding.TxOut {
		if bytes.Equal(out.PkScript, feeScript) {
			fundingIndex = i
		}
	}
	require.GreaterOrEqual(t, fundingIndex, 0)
	feePoint := wire.OutPoint{Hash: funding.TxHash(), Index: uint32(fundingIndex)}
	child := wire.NewMsgTx(3)
	anchorPoint := wire.OutPoint{Hash: restoredParent.TxHash(), Index: 1}
	child.AddTxIn(&wire.TxIn{PreviousOutPoint: anchorPoint, Sequence: wire.MaxTxInSequenceNum})
	child.AddTxIn(&wire.TxIn{PreviousOutPoint: feePoint, Sequence: wire.MaxTxInSequenceNum})
	child.AddTxOut(wire.NewTxOut(16000, feeScript)) // 4,000 sats pay for parent+child.
	multi := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{anchorPoint: wire.NewTxOut(0, anchor), feePoint: funding.TxOut[fundingIndex]})
	childHash, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(child, multi), txscript.SigHashDefault, child, 1, multi)
	require.NoError(t, err)
	tweaked := txscript.TweakTaprootPrivKey(*user, nil)
	childSig, err := schnorr.Sign(tweaked, childHash)
	tweaked.Zero()
	require.NoError(t, err)
	child.TxIn[1].Witness = wire.TxWitness{childSig.Serialize()}
	var submission struct {
		Message string `json:"package_msg"`
	}
	rpc.must(t, "submitpackage", []any{[]string{txHex(t, restoredParent), txHex(t, child)}}, &submission)
	require.Equal(t, "success", submission.Message)
	mine(1)

	destinationKey := fixtureSeedKey(t, mnemonic, 1)
	defer destinationKey.Zero()
	destinationScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(destinationKey.PubKey()))
	require.NoError(t, err)
	sweep := wire.NewMsgTx(2)
	sweep.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: restoredParent.TxHash(), Index: 0}, Sequence: 6})
	sweep.AddTxOut(wire.NewTxOut(restored.Amount-2000, destinationScript))
	sweepPrev := txscript.NewCannedPrevOutputFetcher(restored.Script, restored.Amount)
	sweepHash, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(sweep, sweepPrev), txscript.SigHashDefault, sweep, 0, sweepPrev, txscript.NewBaseTapLeaf(restored.ExitLeaf))
	require.NoError(t, err)
	sweepSig, err := schnorr.Sign(user, sweepHash)
	require.NoError(t, err)
	sweep.TxIn[0].Witness = wire.TxWitness{sweepSig.Serialize(), restored.ExitLeaf, restored.ControlBlock}
	var early []struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reject-reason"`
	}
	rpc.must(t, "testmempoolaccept", []any{[]string{txHex(t, sweep)}}, &early)
	require.Len(t, early, 1)
	require.False(t, early[0].Allowed)
	require.Contains(t, early[0].Reason, "non-BIP68-final")
	mine(6)
	rpc.must(t, "sendrawtransaction", []any{txHex(t, sweep)}, nil)
	mine(1)
	var payout struct {
		Value         float64 `json:"value"`
		Confirmations int     `json:"confirmations"`
		Script        struct {
			Hex string `json:"hex"`
		} `json:"scriptPubKey"`
	}
	rpc.must(t, "gettxout", []any{sweep.TxID(), 0}, &payout)
	require.GreaterOrEqual(t, payout.Confirmations, 1)
	require.InDelta(t, 0.00098, payout.Value, 0.000000001)
	require.Equal(t, hex.EncodeToString(destinationScript), payout.Script.Hex)
	var oldOutput json.RawMessage
	rpc.must(t, "gettxout", []any{restoredParent.TxID(), 0}, &oldOutput)
	require.Equal(t, "null", string(oldOutput))
	// Public regtest evidence only. No mnemonic, private key or raw capsule.
	if path := os.Getenv("RECOVERY_BITCOIN_EVIDENCE"); path != "" {
		evidence := map[string]any{"kind": "bitcoin_fixture", "chain": "regtest", "commitment_txid": restoredCommit.UnsignedTx.TxID(), "replacement_outpoint": restored.Replacement, "ciphertext_sha256": page.Records[0].Hash, "captured_at_height": captureHeight, "funding_txid": fundingID, "sweep_txid": sweep.TxID(), "received_sats": 98000, "confirmed": true, "late_funding": true, "early_sweep_rejected": true, "arkd_round": false}
		data, e := json.MarshalIndent(evidence, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(path, data, 0600))
	}
}
