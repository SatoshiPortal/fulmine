package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/ArkLabsHQ/fulmine/api-spec/protobuf/gen/go/delegate/v1"
	arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type liveConfig struct {
	Ark, Admin, Explorer, Delegate, Backup, Workdir, Bitcoin string
	MiningAddress                                            string `json:"mining_address"`
}

func liveConfigFor(t *testing.T) liveConfig {
	t.Helper()
	path := os.Getenv("RECOVERY_LIVE_CONFIG")
	if path == "" {
		t.Skip("requires owned live Arkade stack")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var cfg liveConfig
	require.NoError(t, json.Unmarshal(raw, &cfg))
	return cfg
}
func liveNostrKey(t *testing.T, mnemonic string) *btcec.PrivateKey {
	seed := bip39.NewSeed(mnemonic, "")
	defer clear(seed)
	key, err := bip32.NewMasterKey(seed)
	require.NoError(t, err)
	for _, child := range []uint32{0x8000002c, 0x800004d5, 0x80000000, 0, 0} {
		key, err = key.NewChildKey(child)
		require.NoError(t, err)
	}
	private, _ := btcec.PrivKeyFromBytes(key.Key)
	return private
}
func TestLivePrepare(t *testing.T) {
	cfg := liveConfigFor(t)
	ctx := t.Context()
	entropy, err := bip39.NewEntropy(256)
	require.NoError(t, err)
	mnemonic, err := bip39.NewMnemonic(entropy)
	require.NoError(t, err)
	clear(entropy)
	require.NoError(t, os.WriteFile(filepath.Join(cfg.Workdir, "seed"), []byte(mnemonic), 0600))
	alice, err := arksdk.NewWallet(filepath.Join(cfg.Workdir, "wallet"))
	require.NoError(t, err)
	defer alice.Stop()
	require.NoError(t, alice.Init(ctx, cfg.Ark, mnemonic, "password", arksdk.WithExplorerURL(cfg.Explorer)))
	require.NoError(t, alice.Unlock(ctx, "password"))
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case state := <-alice.IsSynced(syncCtx):
		require.NoError(t, state.Err)
		require.True(t, state.Synced)
	case <-syncCtx.Done():
		t.Fatal("wallet sync timeout")
	}
	owner := fixtureSeedKey(t, mnemonic, 0)
	defer owner.Zero()
	ref, err := alice.Identity().GetKey(ctx, "m/0/0")
	require.NoError(t, err)
	require.True(t, ref.PubKey.IsEqual(owner.PubKey()))
	alicePubKey := owner.PubKey()

	conn, err := grpc.NewClient(cfg.Delegate, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	delegateClient := pb.NewDelegateServiceClient(conn)
	require.NoError(t, err)
	require.NotNil(t, delegateClient)

	delegateInfo, err := delegateClient.GetDelegateInfo(ctx, &pb.GetDelegateInfoRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, delegateInfo.GetPubkey())
	require.NotEmpty(t, delegateInfo.GetFee())

	delegatePubKeyBytes, err := hex.DecodeString(delegateInfo.GetPubkey())
	require.NoError(t, err)
	delegatePubKey, err := btcec.ParsePubKey(delegatePubKeyBytes)
	require.NoError(t, err)
	require.NotNil(t, delegatePubKey)

	_, aliceAddr, _, _, err := alice.GetAddresses(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceAddr)

	aliceArkAddr, err := arklib.DecodeAddressV0(aliceAddr[0])
	require.NoError(t, err)
	require.NotNil(t, aliceArkAddr)

	aliceConfig, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	signerPubKey := aliceConfig.SignerPubKey

	aliceDelegatorClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{alicePubKey, delegatePubKey, signerPubKey},
	}

	exitLocktime := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: 5,
	}

	delegatorVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			aliceDelegatorClosure,
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{alicePubKey, signerPubKey},
			},
			&script.CSVMultisigClosure{
				Locktime: exitLocktime,
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{alicePubKey},
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := delegatorVtxoScript.TapTree()
	require.NoError(t, err)

	arkAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     signerPubKey,
	}

	arkAddressStr, err := arkAddress.EncodeV0()
	require.NoError(t, err)

	var notes struct {
		Notes []string `json:"notes"`
	}
	require.NoError(t, Post(ctx, NewHTTPClient(), cfg.Admin+"/v1/admin/note", map[string]string{"amount": "21000"}, &notes))
	require.Len(t, notes.Notes, 1)
	_, err = alice.RedeemNotes(ctx, notes.Notes)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		v, _, e := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
		return e == nil && len(v) > 0
	}, 15*time.Second, 200*time.Millisecond)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var incomingFunds []clientTypes.Vtxo
	var incomingErr error
	go func() {
		incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, arkAddressStr)
		wg.Done()
	}()
	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     arkAddressStr,
		Amount: 21000,
	}})
	require.NoError(t, err)

	wg.Wait()
	require.NoError(t, incomingErr)
	require.NotEmpty(t, incomingFunds)

	aliceVtxo := incomingFunds[0]

	intentMessage := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		CosignersPublicKeys: []string{delegateInfo.GetPubkey()},
		ValidAt:             time.Now().Add(3 * time.Second).Unix(),
		ExpireAt:            0,
	}

	encodedIntentMessage, err := intentMessage.Encode()
	require.NoError(t, err)

	vtxoHash, err := chainhash.NewHashFromStr(aliceVtxo.Txid)
	require.NoError(t, err)

	exitScript, err := delegatorVtxoScript.ExitClosures()[0].Script()
	require.NoError(t, err)

	exitScriptMerkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(exitScript).TapHash(),
	)
	require.NoError(t, err)

	sequence, err := arklib.BIP68Sequence(exitLocktime)
	require.NoError(t, err)

	delegatorPkScript, err := arkAddress.GetPkScript()
	require.NoError(t, err)

	alicePkScript, err := aliceArkAddr.GetPkScript()
	require.NoError(t, err)

	intentProof, err := intent.New(
		encodedIntentMessage,
		[]intent.Input{
			{
				OutPoint: &wire.OutPoint{
					Hash:  *vtxoHash,
					Index: aliceVtxo.VOut,
				},
				Sequence: sequence,
				WitnessUtxo: &wire.TxOut{
					Value:    int64(aliceVtxo.Amount),
					PkScript: delegatorPkScript,
				},
			},
		},
		[]*wire.TxOut{
			{
				Value:    int64(aliceVtxo.Amount),
				PkScript: alicePkScript,
			},
		},
	)
	require.NoError(t, err)

	tapLeafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: exitScriptMerkleProof.ControlBlock,
		Script:       exitScriptMerkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	intentProof.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeafScript}
	intentProof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeafScript}

	scripts, err := delegatorVtxoScript.Encode()
	require.NoError(t, err)

	tapTree := txutils.TapTree(scripts)

	err = txutils.SetArkPsbtField(&intentProof.Packet, 1, txutils.VtxoTaprootTreeField, tapTree)
	require.NoError(t, err)

	unsignedIntentProof, err := intentProof.B64Encode()
	require.NoError(t, err)

	// Identity-level for the same reason as the forfeit below: the proof spends
	// the hand-built delegatorVtxoScript, which the contract manager cannot
	// resolve, so the wallet-level call would leave that input unsigned.
	signedIntentProof, err := alice.Identity().SignTransaction(ctx, unsignedIntentProof, map[string]string{hex.EncodeToString(delegatorPkScript): "m/0/0"})
	require.NoError(t, err)
	require.NotEqual(t, unsignedIntentProof, signedIntentProof, "intent proof came back unsigned")

	signedIntentProofPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedIntentProof), true)
	require.NoError(t, err)

	encodedIntentProof, err := signedIntentProofPsbt.B64Encode()
	require.NoError(t, err)

	forfeitOutputAddr, err := btcutil.DecodeAddress(aliceConfig.ForfeitAddress, nil)
	require.NoError(t, err)

	forfeitOutputScript, err := txscript.PayToAddrScript(forfeitOutputAddr)
	require.NoError(t, err)

	connectorAmount := aliceConfig.Dust

	partialForfeitTx, err := tree.BuildForfeitTxWithOutput(
		[]*wire.OutPoint{{
			Hash:  *vtxoHash,
			Index: aliceVtxo.VOut,
		}},
		[]uint32{wire.MaxTxInSequenceNum},
		[]*wire.TxOut{{
			Value:    int64(aliceVtxo.Amount),
			PkScript: delegatorPkScript,
		}},
		&wire.TxOut{
			Value:    int64(aliceVtxo.Amount + connectorAmount),
			PkScript: forfeitOutputScript,
		},
		0,
	)
	require.NoError(t, err)

	updater, err := psbt.NewUpdater(partialForfeitTx)
	require.NoError(t, err)
	require.NotNil(t, updater)

	err = updater.AddInSighashType(txscript.SigHashAnyOneCanPay|txscript.SigHashAll, 0)
	require.NoError(t, err)

	aliceDelegatorScript, err := aliceDelegatorClosure.Script()
	require.NoError(t, err)

	aliceDelegatorMerkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(aliceDelegatorScript).TapHash(),
	)
	require.NoError(t, err)

	aliceDelegatorTapLeafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: aliceDelegatorMerkleProof.ControlBlock,
		Script:       aliceDelegatorMerkleProof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	updater.Upsbt.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{aliceDelegatorTapLeafScript}

	b64partialForfeitTx, err := updater.Upsbt.B64Encode()
	require.NoError(t, err)

	// Sign via the identity, not the wallet. The vtxo lives under the hand-built
	// delegatorVtxoScript above, which alice's contract manager never registered,
	// so wallet.SignTransaction's getKeys lookup resolves nothing and it returns
	// the tx UNSIGNED with a nil error (go-sdk sign.go:39). Alice is a party to
	// aliceDelegatorClosure, so her single-key identity — which ignores the key
	// map entirely — signs it correctly.
	signedPartialForfeitTx, err := alice.Identity().SignTransaction(ctx, b64partialForfeitTx, map[string]string{hex.EncodeToString(delegatorPkScript): "m/0/0"})
	require.NoError(t, err)
	require.NotEqual(t, b64partialForfeitTx, signedPartialForfeitTx, "forfeit came back unsigned")

	// Bind the full replacement contract to the seed-derived owner.
	outputContract := script.NewDefaultVtxoScript(owner.PubKey(), signerPubKey, aliceConfig.UnilateralExitDelay)
	tapscripts, err := outputContract.Encode()
	require.NoError(t, err)
	outputKey, _, err := outputContract.TapTree()
	require.NoError(t, err)
	outputScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(alicePkScript), hex.EncodeToString(outputScript), "SDK first address must match seed key")
	outputs := []Output{{Script: hex.EncodeToString(outputScript), Tapscripts: tapscripts, KeyPath: "m/0/0"}}
	nostr := liveNostrKey(t, mnemonic)
	defer nostr.Zero()
	grant := testGrant(t, nostr, delegateInfo.GetRecoveryPublisher(), cfg.Backup)
	grant.Scope = Scope(encodedIntentMessage, encodedIntentProof, outputs)
	grant.Signature, err = Sign(nostr, grant.Digest())
	require.NoError(t, err)
	ownerSig, err := Sign(owner, grant.Digest())
	require.NoError(t, err)
	reg := Registration{Grant: grant, Outputs: outputs, OwnerSignatures: map[string]string{Public(owner): ownerSig}}
	registration, err := json.Marshal(reg)
	require.NoError(t, err)
	req := &pb.DelegateRequest{Intent: &pb.Intent{Message: encodedIntentMessage, Proof: encodedIntentProof}, ForfeitTxs: []string{signedPartialForfeitTx}, RecoveryRegistration: string(registration)}
	raw, err := protojson.Marshal(req)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfg.Workdir, "protected-request.json"), raw, 0600))
	raw, err = json.Marshal(map[string]any{"original_outpoint": aliceVtxo.Outpoint.String(), "nostr_public_key": Public(nostr), "wallet_identity": "go-sdk HD BIP86", "nostr_path": "m/44'/1237'/0'/0/0"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfg.Workdir, "prepare-evidence.json"), raw, 0600))
}

func TestLiveRestore(t *testing.T) {
	cfg := liveConfigFor(t)
	raw, err := os.ReadFile(filepath.Join(cfg.Workdir, "seed"))
	require.NoError(t, err)
	mnemonic := string(raw)
	clear(raw)
	user := fixtureSeedKey(t, mnemonic, 0)
	defer user.Zero()
	nostr := liveNostrKey(t, mnemonic)
	defer nostr.Zero()
	page, err := FetchPage(t.Context(), cfg.Backup, nostr, 0, 0)
	require.NoError(t, err)
	require.Len(t, page.Records, 1)
	plaintext, err := Open(page.Records[0], nostr)
	require.NoError(t, err)
	defer clear(plaintext)
	var bundle struct {
		Version        int                             `json:"version"`
		Network        string                          `json:"network"`
		Commitment     string                          `json:"commitment_psbt"`
		CommitmentTxID string                          `json:"commitment_txid"`
		Branch         []string                        `json:"branch_psbts"`
		Replacement    string                          `json:"replacement_outpoint"`
		Registration   Registration                    `json:"registration"`
		Intent         struct{ Message, Proof string } `json:"intent"`
	}
	require.NoError(t, json.Unmarshal(plaintext, &bundle))
	require.Equal(t, 1, bundle.Version)
	require.Equal(t, "regtest", bundle.Network)
	reg := bundle.Registration
	require.Len(t, reg.Outputs, 1)
	require.Equal(t, page.Records[0].Grant, reg.Grant)
	require.Equal(t, Scope(bundle.Intent.Message, bundle.Intent.Proof, reg.Outputs), reg.Grant.Scope)
	require.NoError(t, Verify(Public(user), reg.Grant.Digest(), reg.OwnerSignatures[Public(user)]))
	var contract script.TapscriptsVtxoScript
	require.NoError(t, contract.Decode(reg.Outputs[0].Tapscripts))
	key, merkle, err := contract.TapTree()
	require.NoError(t, err)
	outputScript, err := txscript.PayToTaprootScript(key)
	require.NoError(t, err)
	require.Equal(t, reg.Outputs[0].Script, hex.EncodeToString(outputScript))
	exits := contract.ExitClosures()
	require.Len(t, exits, 1)
	exit, ok := exits[0].(*script.CSVMultisigClosure)
	require.True(t, ok)
	require.Len(t, exit.PubKeys, 1)
	require.True(t, exit.PubKeys[0].IsEqual(user.PubKey()))
	exitLeaf, err := exit.Script()
	require.NoError(t, err)
	control, err := merkle.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(exitLeaf).TapHash())
	require.NoError(t, err)
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(bundle.Commitment), true)
	require.NoError(t, err)
	require.Equal(t, bundle.CommitmentTxID, commitment.UnsignedTx.TxID())
	require.NotEmpty(t, bundle.Branch)
	packets := make([]*psbt.Packet, len(bundle.Branch))
	var root, last *tree.TxTree
	for i, encoded := range bundle.Branch {
		packets[i], err = psbt.NewFromRawBytes(strings.NewReader(encoded), true)
		require.NoError(t, err)
		node := &tree.TxTree{Root: packets[i]}
		if root == nil {
			root = node
		} else {
			last.Children = map[uint32]*tree.TxTree{packets[i].UnsignedTx.TxIn[0].PreviousOutPoint.Index: node}
		}
		last = node
	}
	replacement, err := wire.NewOutPointFromString(bundle.Replacement)
	require.NoError(t, err)
	leaf := packets[len(packets)-1].UnsignedTx
	require.Equal(t, replacement.Hash, leaf.TxHash())
	require.Less(t, int(replacement.Index), len(leaf.TxOut))
	amount := leaf.TxOut[replacement.Index].Value
	_, point, err := ExtractBranch(root, commitment, outputScript, amount)
	require.NoError(t, err)
	require.Equal(t, bundle.Replacement, point)
	rpc := bitcoinRPC{url: cfg.Bitcoin, client: &http.Client{Timeout: 20 * time.Second}}
	faucet := bitcoinRPC{url: cfg.Bitcoin + "/wallet/faucet", client: rpc.client}
	var info struct{ Chain string }
	rpc.must(t, "getblockchaininfo", nil, &info)
	require.Equal(t, "regtest", info.Chain)
	mine := func(n int) { rpc.must(t, "generatetoaddress", []any{n, cfg.MiningAddress}, nil) }
	var committed struct {
		Confirmations int    `json:"confirmations"`
		Hex           string `json:"hex"`
	}
	rpc.must(t, "getrawtransaction", []any{bundle.CommitmentTxID, true}, &committed)
	require.Positive(t, committed.Confirmations)
	require.Equal(t, commitment.UnsignedTx.TxHash(), decodeTx(t, committed.Hex).TxHash())
	var ancestor json.RawMessage
	rpc.must(t, "gettxout", []any{bundle.CommitmentTxID, packets[0].UnsignedTx.TxIn[0].PreviousOutPoint.Index}, &ancestor)
	require.NotEqual(t, "null", string(ancestor), "commitment ancestor is already spent")
	feeKey := txscript.ComputeTaprootKeyNoScript(user.PubKey())
	feeAddress := addressFor(t, feeKey)
	feeScript, err := txscript.PayToTaprootScript(feeKey)
	require.NoError(t, err)
	var scan struct {
		Total float64 `json:"total_amount"`
	}
	rpc.must(t, "scantxoutset", []any{"start", []string{"addr(" + feeAddress + ")"}}, &scan)
	require.Zero(t, scan.Total, "fees must be absent until after retrieval and verification")
	var fundingID, fundingRaw string
	faucet.must(t, "sendtoaddress", []any{feeAddress, 0.001}, &fundingID)
	mine(1)
	rpc.must(t, "getrawtransaction", []any{fundingID}, &fundingRaw)
	funding := decodeTx(t, fundingRaw)
	var feePoint wire.OutPoint
	var feeOutput *wire.TxOut
	for i, out := range funding.TxOut {
		if bytes.Equal(out.PkScript, feeScript) {
			feePoint = wire.OutPoint{Hash: funding.TxHash(), Index: uint32(i)}
			feeOutput = out
		}
	}
	require.NotNil(t, feeOutput)
	for _, packet := range packets {
		parent := packet.UnsignedTx.Copy()
		parent.TxIn[0].Witness = wire.TxWitness{packet.Inputs[0].TaprootKeySpendSig}
		anchorIndex := -1
		for i, out := range parent.TxOut {
			if bytes.Equal(out.PkScript, []byte{0x51, 0x02, 0x4e, 0x73}) {
				anchorIndex = i
			}
		}
		require.GreaterOrEqual(t, anchorIndex, 0, "real branch needs its anchor for later fee funding")
		anchorPoint := wire.OutPoint{Hash: parent.TxHash(), Index: uint32(anchorIndex)}
		child := wire.NewMsgTx(3)
		child.AddTxIn(&wire.TxIn{PreviousOutPoint: anchorPoint, Sequence: wire.MaxTxInSequenceNum})
		child.AddTxIn(&wire.TxIn{PreviousOutPoint: feePoint, Sequence: wire.MaxTxInSequenceNum})
		child.AddTxOut(wire.NewTxOut(feeOutput.Value-4000, feeScript))
		require.Positive(t, child.TxOut[0].Value)
		prev := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{anchorPoint: parent.TxOut[anchorIndex], feePoint: feeOutput})
		hash, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(child, prev), txscript.SigHashDefault, child, 1, prev)
		require.NoError(t, err)
		tweaked := txscript.TweakTaprootPrivKey(*user, nil)
		sig, err := schnorr.Sign(tweaked, hash)
		tweaked.Zero()
		require.NoError(t, err)
		child.TxIn[1].Witness = wire.TxWitness{sig.Serialize()}
		var submitted struct {
			Message string `json:"package_msg"`
		}
		rpc.must(t, "submitpackage", []any{[]string{txHex(t, parent), txHex(t, child)}}, &submitted)
		require.Equal(t, "success", submitted.Message)
		mine(1)
		feePoint = wire.OutPoint{Hash: child.TxHash(), Index: 0}
		feeOutput = child.TxOut[0]
	}
	destination := fixtureSeedKey(t, mnemonic, 1)
	defer destination.Zero()
	destinationScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(destination.PubKey()))
	require.NoError(t, err)
	sequence, err := arklib.BIP68Sequence(exit.Locktime)
	require.NoError(t, err)
	require.Equal(t, arklib.LocktimeTypeBlock, exit.Locktime.Type)
	sweep := wire.NewMsgTx(2)
	sweep.AddTxIn(&wire.TxIn{PreviousOutPoint: *replacement, Sequence: sequence})
	sweep.AddTxOut(wire.NewTxOut(amount-2000, destinationScript))
	prev := txscript.NewCannedPrevOutputFetcher(outputScript, amount)
	hash, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(sweep, prev), txscript.SigHashDefault, sweep, 0, prev, txscript.NewBaseTapLeaf(exitLeaf))
	require.NoError(t, err)
	sig, err := schnorr.Sign(user, hash)
	require.NoError(t, err)
	sweep.TxIn[0].Witness = wire.TxWitness{sig.Serialize(), exitLeaf, control.ControlBlock}
	var early []struct {
		Allowed bool
		Reason  string `json:"reject-reason"`
	}
	rpc.must(t, "testmempoolaccept", []any{[]string{txHex(t, sweep)}}, &early)
	require.Len(t, early, 1)
	require.False(t, early[0].Allowed)
	require.Contains(t, early[0].Reason, "non-BIP68-final")
	mine(int(exit.Locktime.Value))
	rpc.must(t, "sendrawtransaction", []any{txHex(t, sweep)}, nil)
	mine(1)
	var payout struct {
		Value         float64
		Confirmations int
		Script        struct{ Hex string } `json:"scriptPubKey"`
	}
	rpc.must(t, "gettxout", []any{sweep.TxID(), 0}, &payout)
	require.Positive(t, payout.Confirmations)
	require.Equal(t, hex.EncodeToString(destinationScript), payout.Script.Hex)
	require.InDelta(t, float64(amount-2000)/1e8, payout.Value, 1e-9)
	rpc.must(t, "gettxout", []any{replacement.Hash.String(), replacement.Index}, &ancestor)
	require.Equal(t, "null", string(ancestor))
	evidence := map[string]any{"arkd_round": true, "commitment_txid": bundle.CommitmentTxID, "replacement_outpoint": bundle.Replacement, "ciphertext_sha256": page.Records[0].Hash, "funding_txid": fundingID, "sweep_txid": sweep.TxID(), "received_sats": amount - 2000, "confirmed": true, "late_funding": true, "nostr_public_key": Public(nostr)}
	raw, err = json.Marshal(evidence)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfg.Workdir, "live-evidence.json"), raw, 0600))
}

func TestLiveWalletReady(t *testing.T) {
	endpoint := os.Getenv("RECOVERY_LIVE_WALLET")
	if endpoint == "" {
		t.Skip("requires live wallet endpoint")
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err := arkwalletv1.NewWalletServiceClient(conn).Status(ctx, &arkwalletv1.StatusRequest{})
		return err == nil
	}, 90*time.Second, time.Second)
}
