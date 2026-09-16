package recovery

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/ArkLabsHQ/fulmine/api-spec/protobuf/gen/go/delegate/v1"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexergrpc "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TestLiveOfflineRenewalBoundary uses only the original public authorization and
// Ark's indexer. It never loads an owner key, decrypts a backup or signs a new
// request. Passing these assertions proves why round two is blocked; it does not
// make the requested multi-refresh acceptance scenario pass.
func TestLiveOfflineRenewalBoundary(t *testing.T) {
	cfg := liveConfigFor(t)
	require.GreaterOrEqual(t, cfg.RequestedRefreshCount, 2)
	require.LessOrEqual(t, cfg.RequestedRefreshCount, 10)
	require.Len(t, cfg.CompletedCommitmentTxID, 64)
	require.Empty(t, cfg.PublicTestMnemonic, "owner seed must not be supplied to the offline probe")
	for _, name := range []string{"seed", "wallet"} {
		_, err := os.Stat(filepath.Join(cfg.Workdir, name))
		require.True(t, os.IsNotExist(err), "owner material still present: %s", name)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.Workdir, "protected-request.json"))
	require.NoError(t, err)
	var original pb.DelegateRequest
	require.NoError(t, protojson.Unmarshal(raw, &original))
	require.NotNil(t, original.Intent)
	require.Len(t, original.ForfeitTxs, 1)
	registration, err := ParseRegistration(original.RecoveryRegistration)
	require.NoError(t, err)
	require.Len(t, registration.Outputs, 1)
	require.NoError(t, Verify(registration.Grant.Owner, registration.Grant.Digest(), registration.Grant.Signature))
	require.Equal(t, registration.Grant.Scope, Scope(original.Intent.Message, original.Intent.Proof, registration.Outputs))
	require.NoError(t, intent.Verify(original.Intent.Proof, original.Intent.Message, nil))

	conn, err := grpc.NewClient(cfg.Delegate, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	delegate := pb.NewDelegateServiceClient(conn)
	info, err := delegate.GetDelegateInfo(t.Context(), &pb.GetDelegateInfoRequest{})
	require.NoError(t, err)
	delegateBytes, err := hex.DecodeString(info.Pubkey)
	require.NoError(t, err)
	delegateKey, err := btcec.ParsePubKey(delegateBytes)
	require.NoError(t, err)
	contract := &script.TapscriptsVtxoScript{}
	require.NoError(t, contract.Decode(registration.Outputs[0].Tapscripts))
	tapKey, _, err := contract.TapTree()
	require.NoError(t, err)
	outputScript, err := txscript.PayToTaprootScript(tapKey)
	require.NoError(t, err)
	require.Equal(t, registration.Outputs[0].Script, hex.EncodeToString(outputScript))
	for _, closure := range contract.Closures {
		var keys []*btcec.PublicKey
		switch c := closure.(type) {
		case *script.MultisigClosure:
			keys = c.PubKeys
		case *script.CSVMultisigClosure:
			keys = c.PubKeys
		default:
			t.Fatalf("unexpected replacement contract %T", closure)
		}
		for _, key := range keys {
			require.False(t, key.IsEqual(delegateKey), "fixture unexpectedly has a delegation key in its replacement")
		}
	}

	idx, err := indexergrpc.NewClient(cfg.Ark)
	require.NoError(t, err)
	defer idx.Close()
	var replacement clientTypes.Vtxo
	require.Eventually(t, func() bool {
		response, err := idx.GetVtxos(t.Context(), indexer.WithScripts([]string{registration.Outputs[0].Script}), indexer.WithSpendableOnly())
		if err != nil {
			return false
		}
		matches := 0
		for _, vtxo := range response.Vtxos {
			if slices.Contains(vtxo.CommitmentTxids, cfg.CompletedCommitmentTxID) {
				replacement = vtxo
				matches++
			}
		}
		return matches == 1
	}, 15*time.Second, 200*time.Millisecond, "replacement must come from the completed commitment")
	require.False(t, replacement.Spent)
	require.False(t, replacement.Unrolled)
	replacementPoint, err := wire.NewOutPointFromString(replacement.Outpoint.String())
	require.NoError(t, err)
	forfeit, err := psbt.NewFromRawBytes(strings.NewReader(original.ForfeitTxs[0]), true)
	require.NoError(t, err)
	require.True(t, renewalForfeitSignatureValid(t, forfeit), "baseline owner signature must verify")
	originalPoint := forfeit.UnsignedTx.TxIn[0].PreviousOutPoint
	require.NotEqual(t, originalPoint, *replacementPoint)
	old, err := idx.GetVtxos(t.Context(), indexer.WithOutpoints([]clientTypes.Outpoint{{Txid: originalPoint.Hash.String(), VOut: originalPoint.Index}}))
	require.NoError(t, err)
	require.Len(t, old.Vtxos, 1)
	require.True(t, old.Vtxos[0].Spent)

	// ANYONECANPAY permits adding the connector input. It does not permit
	// substituting a different user input. Change only that outpoint to isolate
	// this signature boundary, even before correcting the replacement contract.
	forfeit.UnsignedTx.TxIn[0].PreviousOutPoint = *replacementPoint
	require.False(t, renewalForfeitSignatureValid(t, forfeit))
	changedForfeit, err := forfeit.B64Encode()
	require.NoError(t, err)
	proof, err := psbt.NewFromRawBytes(strings.NewReader(original.Intent.Proof), true)
	require.NoError(t, err)
	require.Len(t, proof.UnsignedTx.TxIn, 2)
	require.Equal(t, originalPoint, proof.UnsignedTx.TxIn[1].PreviousOutPoint)
	proof.UnsignedTx.TxIn[1].PreviousOutPoint = *replacementPoint
	changedProof, err := proof.B64Encode()
	require.NoError(t, err)
	intentErr := intent.Verify(changedProof, original.Intent.Message, nil)
	require.Error(t, intentErr)
	changedScope := Scope(original.Intent.Message, changedProof, registration.Outputs)
	require.NotEqual(t, registration.Grant.Scope, changedScope)
	changedGrant := registration.Grant
	changedGrant.Scope = changedScope
	grantErr := Verify(changedGrant.Owner, changedGrant.Digest(), changedGrant.Signature)
	require.Error(t, grantErr, "rewriting scope cannot preserve the owner's grant signature")

	_, replayErr := delegate.Delegate(t.Context(), &original)
	require.Equal(t, codes.Internal, status.Code(replayErr))
	require.ErrorContains(t, replayErr, "already spent")
	retargeted := proto.Clone(&original).(*pb.DelegateRequest)
	retargeted.Intent.Proof = changedProof
	retargeted.ForfeitTxs = []string{changedForfeit}
	_, retargetErr := delegate.Delegate(t.Context(), retargeted)
	require.Equal(t, codes.Internal, status.Code(retargetErr))
	require.ErrorContains(t, retargetErr, "invalid forfeit signature")

	current, err := idx.GetVtxos(t.Context(), indexer.WithOutpoints([]clientTypes.Outpoint{replacement.Outpoint}))
	require.NoError(t, err)
	require.Len(t, current.Vtxos, 1)
	require.False(t, current.Vtxos[0].Spent)
	require.False(t, current.Vtxos[0].Unrolled)
	checks := map[string]bool{}
	for _, name := range []string{
		"wallet_state_absent", "seed_file_absent", "config_seed_absent",
		"original_intent_signature_valid", "retargeted_intent_signature_rejected",
		"original_forfeit_signature_valid", "retargeted_forfeit_signature_rejected",
		"retargeted_scope_differs", "rewritten_grant_signature_rejected",
		"replacement_has_no_delegate_key", "original_request_rejected", "retargeted_request_rejected",
		"original_input_spent", "replacement_unspent",
	} {
		checks[name] = true // Emitted only after all corresponding assertions pass.
	}
	evidence := map[string]any{
		"status": "blocked", "requested_refresh_count": cfg.RequestedRefreshCount,
		"completed_refresh_count": 1, "blocked_round": 2,
		"blocked_reason":  "The replacement requires a new owner-signed intent and forfeit, and a new recovery grant scope. The original authorization cannot be reused while the owner remains offline.",
		"commitment_txid": cfg.CompletedCommitmentTxID, "replacement_outpoint": replacement.Outpoint.String(),
		"checks": checks, "rejections": map[string]string{
			"original_request": replayErr.Error(), "retargeted_request": retargetErr.Error(),
			"intent": intentErr.Error(), "grant": grantErr.Error(),
		},
	}
	raw, err = json.MarshalIndent(evidence, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfg.Workdir, "offline-renewal-evidence.json"), raw, 0600))
}

func renewalForfeitSignatureValid(t *testing.T, packet *psbt.Packet) bool {
	t.Helper()
	require.Len(t, packet.Inputs, 1)
	require.Len(t, packet.Inputs[0].TaprootScriptSpendSig, 1)
	require.Len(t, packet.Inputs[0].TaprootLeafScript, 1)
	in := packet.Inputs[0]
	signed := in.TaprootScriptSpendSig[0]
	require.Equal(t, txscript.SigHashAll|txscript.SigHashAnyOneCanPay, signed.SigHash)
	previous := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		packet.UnsignedTx.TxIn[0].PreviousOutPoint: in.WitnessUtxo,
	})
	leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
	message, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(packet.UnsignedTx, previous), signed.SigHash, packet.UnsignedTx, 0, previous, leaf)
	require.NoError(t, err)
	key, err := schnorr.ParsePubKey(signed.XOnlyPubKey)
	require.NoError(t, err)
	signature, err := schnorr.ParseSignature(signed.Signature)
	require.NoError(t, err)
	return signature.Verify(message, key)
}
