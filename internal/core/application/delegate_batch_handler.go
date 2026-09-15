package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	indexer "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// Batch session handler of the delegate service
type delegateBatchSessionHandler struct {
	musig2BatchSessionHandler
	delegate        *DelegateService
	selectedTasks   []registeredIntent
	recoveryAttempt *recoveryAttempt
}

// BatchStarted event doesn't have to be handled by the delegate session
// it is handled before creating the handler in a dedicated goroutine.
func (h *delegateBatchSessionHandler) OnBatchStarted(
	context.Context, client.BatchStartedEvent,
) (bool, error) {
	return true, nil
}

// OnBatchFinalized mark the delegates as done and delete the intent from the registered
// intents map
func (h *delegateBatchSessionHandler) OnBatchFinalized(
	ctx context.Context, event client.BatchFinalizedEvent,
) error {
	if h.delegate.recovery != nil {
		a := h.recoveryAttempt
		if a == nil || (a.phase != recoverySubmitted && a.phase != recoverySubmissionUnknown) ||
			a.batchID != event.Id || a.txid != event.Txid || !slices.Equal(a.taskIDs, h.taskIDs()) {
			return h.failRecovery(ctx, fmt.Errorf("finalized commitment does not match protected attempt"))
		}
		// Record the matching final event before the task DB update. Restart can
		// replay this one idempotent update without submitting anything to Ark.
		if err := h.saveRecoveryPhase(ctx, recovery.AttemptFinalized); err != nil {
			return err
		}
	}
	repo := h.delegate.svc.dbSvc.Delegate()
	if err := repo.CompleteTasks(ctx, event.Txid, h.taskIDs()...); err != nil {
		return err
	}
	taskIds := make([]string, 0, len(h.selectedTasks))
	for _, selectedTask := range h.selectedTasks {
		taskIds = append(taskIds, selectedTask.taskID)
		h.delegate.intentsMtx.Lock()
		delete(h.delegate.registeredIntents, selectedTask.intentIDHash())
		h.delegate.intentsMtx.Unlock()
	}

	return nil
}

// OnBatchFailed re-register the delegates that failed to join the batch
func (h *delegateBatchSessionHandler) OnBatchFailed(
	ctx context.Context, event client.BatchFailedEvent,
) error {
	if h.delegate.recovery != nil && h.recoveryAttempt != nil {
		return h.failRecovery(ctx, fmt.Errorf("protected batch failed; retained candidate requires reconciliation"))
	}
	for _, selectedTask := range h.selectedTasks {
		if err := h.delegate.registerDelegate(selectedTask.taskID); err != nil {
			log.WithError(err).Warnf("failed to re-register delegate %s", selectedTask.taskID)
			continue
		}
	}
	log.Warnf("batch failed, %d delegates re-registered", len(h.selectedTasks))
	return fmt.Errorf("batch failed")
}

// OnBatchFinalization submit the delegated forfeit transactions to arkd
func (h *delegateBatchSessionHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) error {
	if h.delegate.recovery != nil {
		return h.finalizeRecovery(ctx, event, func() (map[string]string, error) {
			if connectorTree == nil || len(connectorTree.Leaves()) == 0 {
				return nil, fmt.Errorf("protected batch has no connectors")
			}
			return h.backupBeforeForfeits(ctx, event, vtxoTree, h.taskIDs())
		}, func() error { return h.submitForfeitTxs(ctx, connectorTree.Leaves(), h.taskIDs()) })
	}
	if connectorTree == nil {
		return fmt.Errorf("batch has no connectors")
	}
	return h.submitForfeitTxs(ctx, connectorTree.Leaves(), h.taskIDs())
}

type recoveryPhase uint8

const (
	recoveryPreparing recoveryPhase = iota
	recoveryAcknowledged
	recoverySubmissionUnknown
	recoverySubmitted
	recoveryFailed
)

type recoveryAttempt struct {
	batchID, txid, eventHash string
	taskIDs                  []string
	receipts                 map[string]string
	phase                    recoveryPhase
	persisted                *recovery.ProtectedAttempt
}

func (h *delegateBatchSessionHandler) taskIDs() []string {
	ids := make([]string, 0, len(h.selectedTasks))
	for _, task := range h.selectedTasks {
		ids = append(ids, task.taskID)
	}
	sort.Strings(ids)
	return ids
}

func (h *delegateBatchSessionHandler) failRecovery(ctx context.Context, cause error) error {
	// A matching final event is terminal evidence even if its task DB update
	// failed. Later stream events cannot revoke that observation or its replay.
	if a := h.recoveryAttempt; a != nil && a.persisted != nil && a.persisted.Phase == recovery.AttemptFinalized {
		return cause
	}
	if h.recoveryAttempt == nil {
		h.recoveryAttempt = &recoveryAttempt{}
	}
	h.recoveryAttempt.phase = recoveryFailed
	// Cancellation must not erase the crash barrier. An earlier durable phase
	// still blocks retry even when this best-effort quarantine annotation fails.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	reason := protectedQuarantinePrefix + " failure before confirmed completion; preserve task and outbox; review attempt before retry"
	var persistErr error
	if a := h.recoveryAttempt.persisted; a != nil {
		if a.QuarantineReason == "" {
			a.QuarantineReason = "protected batch handler failed; preserve evidence and reconcile"
		}
		reason = protectedAttemptReason(*a)
		persistErr = h.delegate.recovery.SaveAttempt(writeCtx, *a)
	}
	err := h.delegate.svc.dbSvc.Delegate().FailTasks(writeCtx, reason, h.taskIDs()...)
	return errors.Join(cause, persistErr, err)
}

func (h *delegateBatchSessionHandler) saveRecoveryPhase(ctx context.Context, phase recovery.AttemptPhase) error {
	a := *h.recoveryAttempt.persisted
	a.Phase = phase
	a.Receipts = h.recoveryAttempt.receipts
	if err := h.delegate.recovery.SaveAttempt(ctx, a); err != nil {
		return err
	}
	h.recoveryAttempt.persisted = &a
	return nil
}

// A disconnected stream is not a failed batch observation. Retain the actual
// last phase and quarantine it; a recorded final event only needs its DB update.
func (h *delegateBatchSessionHandler) abandonRecovery(ctx context.Context) {
	a := h.recoveryAttempt
	if h.delegate.recovery == nil || a == nil || a.phase == recoveryFailed || a.persisted == nil || a.persisted.Phase == recovery.AttemptFinalized {
		return
	}
	if err := h.failRecovery(ctx, fmt.Errorf("protected event stream ended before durable finalization")); err != nil {
		log.WithError(err).Warn("protected attempt requires reconciliation")
	}
}

// The callbacks isolate I/O at the two irreversible boundaries. The attempt
// authorizes only this candidate and never repeats an uncertain submission.
func (h *delegateBatchSessionHandler) finalizeRecovery(ctx context.Context, event client.BatchFinalizationEvent,
	backup func() (map[string]string, error), submit func() error,
) error {
	ids := h.taskIDs()
	if a := h.recoveryAttempt; a != nil {
		if a.phase == recoveryFailed {
			return fmt.Errorf("protected attempt already failed")
		}
		if a.batchID != event.Id || a.eventHash != recovery.Hash([]byte(event.Tx)) || !slices.Equal(a.taskIDs, ids) {
			return h.failRecovery(ctx, fmt.Errorf("protected candidate changed"))
		}
		if a.phase == recoverySubmitted {
			return nil
		}
		return fmt.Errorf("protected submission outcome uncertain; await reconciliation")
	}
	h.recoveryAttempt = &recoveryAttempt{batchID: event.Id, eventHash: recovery.Hash([]byte(event.Tx)), taskIDs: ids}
	a := h.recoveryAttempt
	commit, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil || event.Id == "" || len(ids) == 0 {
		return h.failRecovery(ctx, fmt.Errorf("invalid protected candidate"))
	}
	a.txid = commit.UnsignedTx.TxID()
	persisted := recovery.ProtectedAttempt{Version: 1, BatchID: event.Id, CommitmentTxID: a.txid,
		CandidatePSBT: event.Tx, TaskIDs: ids, Phase: recovery.AttemptPreparing}
	if err := h.delegate.recovery.BeginAttempt(ctx, persisted); err != nil {
		// Another handler or a previous process owns this candidate. Do not
		// overwrite its outcome (including an already completed task).
		a.phase = recoveryFailed
		return fmt.Errorf("cannot claim protected attempt: %w", err)
	}
	a.persisted = &persisted
	receipts, err := backup()
	if err != nil {
		return h.failRecovery(ctx, err)
	}
	if len(receipts) != len(ids) {
		return h.failRecovery(ctx, fmt.Errorf("incomplete backup acknowledgements"))
	}
	for _, id := range ids {
		if len(receipts[id]) != 64 {
			return h.failRecovery(ctx, fmt.Errorf("missing task acknowledgement"))
		}
	}
	a.receipts = receipts
	if err := h.saveRecoveryPhase(ctx, recovery.AttemptAcknowledged); err != nil {
		return h.failRecovery(ctx, err)
	}
	a.phase = recoveryAcknowledged
	if err := ctx.Err(); err != nil {
		return h.failRecovery(ctx, err)
	}
	if err := h.saveRecoveryPhase(ctx, recovery.AttemptSubmissionUnknown); err != nil {
		return h.failRecovery(ctx, err)
	}
	a.phase = recoverySubmissionUnknown
	if err := ctx.Err(); err != nil {
		return err
	}
	log.WithFields(log.Fields{"batch": a.batchID, "commitment": a.txid}).Info("recovery forfeits submission starting")
	if err := submit(); err != nil {
		return err
	}
	if err := h.saveRecoveryPhase(ctx, recovery.AttemptSubmitted); err != nil {
		return err
	}
	a.phase = recoverySubmitted
	return nil
}

func (h *delegateBatchSessionHandler) submitForfeitTxs(
	ctx context.Context, connectorsLeaves []*psbt.Packet, selectedTasksIds []string,
) error {
	if len(connectorsLeaves) == 0 {
		if h.delegate.recovery != nil {
			return fmt.Errorf("protected batch has no connectors")
		}
		return nil
	}
	if len(selectedTasksIds) == 0 {
		return nil
	}

	repo := h.delegate.svc.dbSvc.Delegate()
	forfeitTxs := make([]*psbt.Packet, 0)

	for _, selectedTaskId := range selectedTasksIds {
		task, err := repo.GetByID(ctx, selectedTaskId)
		if err != nil {
			return fmt.Errorf("failed to get delegate %s: %w", selectedTaskId, err)
		}

		// include only the forfeit tx of vtxo that are not recoverable
		outpoints := make([]clientTypes.Outpoint, len(task.Intent.Inputs))
		for i, input := range task.Intent.Inputs {
			outpoints[i] = clientTypes.Outpoint{
				Txid: input.Hash.String(),
				VOut: input.Index,
			}
		}

		vtxos, err := h.delegate.svc.Indexer().GetVtxos(ctx, indexer.WithOutpoints(outpoints))
		if err != nil {
			if h.delegate.recovery != nil {
				return fmt.Errorf("protected input lookup failed")
			}
			log.WithError(err).Warnf("failed to get vtxos for task %s", selectedTaskId)
			continue
		}
		if h.delegate.recovery != nil && len(vtxos.Vtxos) != len(outpoints) {
			return fmt.Errorf("protected input lookup incomplete")
		}

		for _, vtxo := range vtxos.Vtxos {
			if vtxo.IsRecoverable() {
				if h.delegate.recovery != nil {
					return fmt.Errorf("protected input became recoverable")
				}
				continue // skip recoverable vtxo
			}

			outpoint, err := wire.NewOutPointFromString(vtxo.Outpoint.String())
			if err != nil {
				if h.delegate.recovery != nil {
					return err
				}
				log.WithError(err).Warnf(
					"failed to parse outpoint for vtxo %s:%d", vtxo.Txid, vtxo.VOut,
				)
				continue
			}

			forfeitTxStr, ok := task.ForfeitTxs[*outpoint]
			if !ok {
				if h.delegate.recovery != nil {
					return fmt.Errorf("protected input has no forfeit")
				}
				continue
			}
			forfeitPtx, err := psbt.NewFromRawBytes(strings.NewReader(forfeitTxStr), true)
			if err != nil {
				return fmt.Errorf("failed to parse forfeit tx: %w", err)
			}
			forfeitTxs = append(forfeitTxs, forfeitPtx)
		}
	}

	if len(forfeitTxs) > len(connectorsLeaves) {
		return fmt.Errorf(
			"insufficient connectors: got %d, need %d",
			len(connectorsLeaves), len(forfeitTxs),
		)
	}

	signedForfeitTxs := make([]string, 0, len(forfeitTxs))
	for i, forfeitTx := range forfeitTxs {
		connectorTx := connectorsLeaves[i]
		connector, connectorOutpoint, err := extractConnector(connectorTx)
		if err != nil {
			return fmt.Errorf("connector not found: %w", err)
		}

		// add the connector to the partially signed forfeit tx
		forfeitTx.Inputs = append(forfeitTx.Inputs, psbt.PInput{
			WitnessUtxo: connector,
		})
		forfeitTx.UnsignedTx.TxIn = append(forfeitTx.UnsignedTx.TxIn, &wire.TxIn{
			PreviousOutPoint: *connectorOutpoint,
			Sequence:         wire.MaxTxInSequenceNum,
		})
		forfeitTx.Inputs[0].SighashType = txscript.SigHashDefault

		if err := signForfeitWithDelegateKey(forfeitTx, h.delegate.svc.privateKey); err != nil {
			return fmt.Errorf("failed to sign forfeit: %w", err)
		}

		signedForfeitTx, err := forfeitTx.B64Encode()
		if err != nil {
			return fmt.Errorf("failed to encode forfeit tx: %w", err)
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return h.delegate.svc.Client().SubmitSignedForfeitTxs(ctx, signedForfeitTxs, "")
}

// musig2BatchSessionHandler implements the Musig2 methods
type musig2BatchSessionHandler struct {
	SweepClosure    script.CSVMultisigClosure
	SignerSession   tree.SignerSession
	TransportClient client.Client
}

func (h *musig2BatchSessionHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	signerPubKey := h.SignerSession.GetPublicKey()
	if !slices.Contains(event.CosignersPubkeys, signerPubKey) {
		return true, nil
	}

	script, err := h.SweepClosure.Script()
	if err != nil {
		return false, fmt.Errorf("failed to get sweep closure script: %w", err)
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, fmt.Errorf("failed to parse commitment tx: %w", err)
	}

	if len(commitmentTx.UnsignedTx.TxOut) == 0 {
		// no tree to sign, skip
		return true, nil
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	if err := h.SignerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
		return false, err
	}

	nonces, err := h.SignerSession.GetNonces()
	if err != nil {
		return false, err
	}

	return false, h.TransportClient.SubmitTreeNonces(ctx, event.Id, h.SignerSession.GetPublicKey(), nonces)
}

func (h *musig2BatchSessionHandler) OnTreeNonces(
	ctx context.Context, event client.TreeNoncesEvent,
) (bool, error) {
	hasAllNonces, err := h.SignerSession.AggregateNonces(event.Txid, event.Nonces)
	if err != nil {
		return false, err
	}

	if !hasAllNonces {
		return false, nil
	}

	sigs, err := h.SignerSession.Sign()
	if err != nil {
		return false, err
	}

	if err := h.TransportClient.SubmitTreeSignatures(
		ctx, event.Id, h.SignerSession.GetPublicKey(), sigs,
	); err != nil {
		return false, err
	}

	return true, nil
}

func (h *musig2BatchSessionHandler) OnTreeNoncesAggregated(
	ctx context.Context, event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	return false, nil
}

func (h *musig2BatchSessionHandler) OnStreamStartedEvent(
	event client.StreamStartedEvent,
) {
}

// signForfeitWithDelegateKey adds the delegate's signature to every tapscript
// leaf of the forfeit's first input that names the delegate's public key.
//
// It deliberately does not go through Wallet.SignTransaction: the vtxo being
// forfeited belongs to the delegator's client, not to us, so the wallet's
// contract manager cannot resolve its script, and Wallet.SignTransaction returns
// the tx UNSIGNED with a nil error in that case (go-sdk sign.go:39) — which arkd
// then rejects as ForfeitInvalidSignature / "missing 1 signatures".
//
// Under the old single-key wallet, Identity().SignTransaction with a nil key map
// signed this correctly, because the wallet's only key was also the delegate
// key. Making HD the default broke that: the HD identity rejects an empty key
// map outright, so signing through it would mean hand-building a
// script -> key-id map for a script the wallet does not own. Signing with the
// delegate key here is the direct route.
//
// Mirrors the single-key identity's signTapscriptSpend, including its use of the
// input's own SighashType, so the bytes produced are unchanged from before.
func signForfeitWithDelegateKey(forfeitTx *psbt.Packet, prvkey *btcec.PrivateKey) error {
	if prvkey == nil {
		return fmt.Errorf("delegate signer key not loaded")
	}
	if len(forfeitTx.Inputs) == 0 {
		return fmt.Errorf("forfeit tx has no inputs")
	}

	// Every input must carry its own prevout: the sighash commits to all of them.
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i := range forfeitTx.Inputs {
		in := forfeitTx.Inputs[i]
		outpoint := forfeitTx.UnsignedTx.TxIn[i].PreviousOutPoint
		if in.WitnessUtxo == nil {
			return fmt.Errorf("forfeit input %d: missing prevout", i)

		}
		prevouts[outpoint] = in.WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsighashes := txscript.NewTxSigHashes(forfeitTx.UnsignedTx, prevoutFetcher)

	myPubkey := schnorr.SerializePubKey(prvkey.PubKey())
	input := forfeitTx.Inputs[0]
	signed := false

	for _, leaf := range input.TaprootLeafScript {
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			continue // unknown leaf, not ours to sign
		}
		if !closureHasPubkey(closure, myPubkey) {
			continue
		}

		leafHash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

		preimage, err := txscript.CalcTapscriptSignaturehash(
			txsighashes, input.SighashType, forfeitTx.UnsignedTx, 0,
			prevoutFetcher, txscript.NewBaseTapLeaf(leaf.Script),
		)
		if err != nil {
			return fmt.Errorf("failed to compute forfeit sighash: %w", err)
		}

		sig, err := schnorr.Sign(prvkey, preimage)
		if err != nil {
			return fmt.Errorf("failed to sign forfeit leaf: %w", err)
		}

		// Append rather than replace: the client's signature is already here, and
		// the closure needs both.
		forfeitTx.Inputs[0].TaprootScriptSpendSig = append(
			forfeitTx.Inputs[0].TaprootScriptSpendSig,
			&psbt.TaprootScriptSpendSig{
				XOnlyPubKey: myPubkey,
				LeafHash:    leafHash.CloneBytes(),
				Signature:   sig.Serialize(),
				SigHash:     input.SighashType,
			},
		)
		signed = true
	}

	if !signed {
		return fmt.Errorf(
			"no tapscript leaf on the forfeit input names the delegate key %x", myPubkey,
		)
	}
	return nil
}

// closureHasPubkey reports whether xonly is one of the closure's signers.
func closureHasPubkey(closure script.Closure, xonly []byte) bool {
	var pubkeys []*btcec.PublicKey
	switch c := closure.(type) {
	case *script.CSVMultisigClosure:
		pubkeys = c.PubKeys
	case *script.MultisigClosure:
		pubkeys = c.PubKeys
	case *script.CLTVMultisigClosure:
		pubkeys = c.PubKeys
	case *script.ConditionMultisigClosure:
		pubkeys = c.PubKeys
	default:
		return false
	}

	for _, key := range pubkeys {
		if bytes.Equal(schnorr.SerializePubKey(key), xonly) {
			return true
		}
	}
	return false
}
