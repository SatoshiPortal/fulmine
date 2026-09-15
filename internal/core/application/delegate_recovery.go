package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArkLabsHQ/fulmine/internal/core/domain"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	indexer "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

func validateRecoveryNetwork(network string) error {
	switch network {
	case "regtest", "mutinynet":
		return nil
	default:
		return fmt.Errorf("recovery prototype supports regtest and mutinynet only (got %q)", network)
	}
}

func (s *DelegateService) configureRecovery(datadir string) error {
	origin := os.Getenv("FULMINE_RECOVERY_PROTOTYPE_URL")
	if origin == "" {
		if _, err := os.Stat(filepath.Join(datadir, "recovery-prototype", "publisher.key")); err == nil {
			return fmt.Errorf("recovery state exists; keep FULMINE_RECOVERY_PROTOTYPE_URL configured")
		} else if !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	manager, err := recovery.NewManager(filepath.Join(datadir, "recovery-prototype"), origin)
	if err != nil {
		return err
	}
	s.recovery = manager
	return nil
}

// Protected prototype mode requires registration for every task, including
// restored tasks. It supports regtest and Mutinynet, with one ordinary user output.
func (s *DelegateService) validateRecovery(ctx context.Context, task *domain.DelegateTask, forfeits []*psbt.Packet, value string) error {
	if s.recovery == nil {
		if value != "" {
			return fmt.Errorf("recovery prototype is disabled")
		}
		return nil
	}
	cfg, err := s.svc.GetConfigData(ctx)
	if err != nil {
		return err
	}
	if err := validateRecoveryNetwork(cfg.Network.Name); err != nil {
		return err
	}
	if value == "" || len(value) > 16*1024 {
		return fmt.Errorf("recovery registration required (maximum 16 KiB)")
	}
	var r recovery.Registration
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&r); err != nil {
		return fmt.Errorf("invalid recovery registration")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing recovery registration data")
	}
	if len(r.Outputs) != 1 || len(r.Outputs[0].Tapscripts) > 3 || len(r.Outputs[0].KeyPath) > 128 {
		return fmt.Errorf("prototype requires one supported replacement output")
	}
	if r.Grant.Scope != recovery.Scope(task.Intent.Message, task.Intent.Proof, r.Outputs) {
		return fmt.Errorf("recovery scope does not match intent and output metadata")
	}
	if len(forfeits) != len(task.Intent.Inputs) || len(task.ForfeitTxs) != len(task.Intent.Inputs) || len(task.Intent.Inputs) == 0 || len(task.Intent.Inputs) > 16 {
		return fmt.Errorf("prototype requires a forfeit for each of at most 16 live inputs")
	}
	owners := make(map[string]bool)
	server := hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerPubKey))
	delegate := hex.EncodeToString(schnorr.SerializePubKey(s.svc.publicKey))
	for _, f := range forfeits {
		if len(f.Inputs) != 1 || len(f.Inputs[0].TaprootLeafScript) != 1 || len(f.Inputs[0].TaprootScriptSpendSig) != 1 {
			return fmt.Errorf("unsupported recovery input")
		}
		leaf := f.Inputs[0].TaprootLeafScript[0]
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			return err
		}
		multisig, ok := closure.(*script.MultisigClosure)
		if !ok || len(multisig.PubKeys) != 3 {
			return fmt.Errorf("prototype requires user+delegate+server input closure")
		}
		keys := make(map[string]bool)
		for _, p := range multisig.PubKeys {
			keys[hex.EncodeToString(schnorr.SerializePubKey(p))] = true
		}
		if len(keys) != 3 || !keys[delegate] || !keys[server] {
			return fmt.Errorf("invalid recovery input parties")
		}
		delete(keys, delegate)
		delete(keys, server)
		for owner := range keys {
			if hex.EncodeToString(f.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey) != owner {
				return fmt.Errorf("forfeit signer is not the input owner")
			}
			if err = recovery.Verify(owner, r.Grant.Digest(), r.OwnerSignatures[owner]); err != nil {
				return fmt.Errorf("missing input-owner authorization for recovery")
			}
			owners[owner] = true
		}
		// Prove the disclosed delegation leaf belongs to the actual input output.
		control, err := txscript.ParseControlBlock(leaf.ControlBlock)
		if err != nil {
			return err
		}
		prev := f.Inputs[0].WitnessUtxo
		if prev == nil || !txscript.IsPayToTaproot(prev.PkScript) {
			return fmt.Errorf("invalid forfeit prevout")
		}
		if err = txscript.VerifyTaprootLeafCommitment(control, prev.PkScript[2:], leaf.Script); err != nil {
			return err
		}
	}
	if len(owners) != 1 {
		return fmt.Errorf("prototype supports a single input owner")
	}
	output := r.Outputs[0]
	var contract script.TapscriptsVtxoScript
	if err = contract.Decode(output.Tapscripts); err != nil {
		return err
	}
	pub, _, err := contract.TapTree()
	if err != nil {
		return err
	}
	pkScript, err := txscript.PayToTaprootScript(pub)
	if err != nil {
		return err
	}
	if hex.EncodeToString(pkScript) != output.Script {
		return fmt.Errorf("output metadata does not reconstruct script")
	}
	exitFound := false
	for _, c := range contract.Closures {
		switch c := c.(type) {
		case *script.CSVMultisigClosure:
			if len(c.PubKeys) != 1 || !owners[hex.EncodeToString(schnorr.SerializePubKey(c.PubKeys[0]))] || c.Locktime.Value == 0 {
				return fmt.Errorf("output exit must belong to input owner")
			}
			exitFound = true
		case *script.MultisigClosure:
			if len(c.PubKeys) < 2 || len(c.PubKeys) > 3 {
				return fmt.Errorf("unsupported output closure")
			}
			participants := make(map[string]bool)
			for _, p := range c.PubKeys {
				key := hex.EncodeToString(schnorr.SerializePubKey(p))
				participants[key] = true
				if key != server && key != delegate && !owners[key] {
					return fmt.Errorf("unexpected output signer")
				}
			}
			if len(participants) != len(c.PubKeys) || !participants[server] {
				return fmt.Errorf("invalid output signing parties")
			}
			for owner := range owners {
				if !participants[owner] {
					return fmt.Errorf("output must require its owner")
				}
			}
		default:
			return fmt.Errorf("custom output contracts are not supported")
		}
	}
	if !exitFound {
		return fmt.Errorf("output has no supported unilateral exit")
	}
	// Check current indexer values against each authorized input's witness UTXO.
	if err = s.recoveryInputs(ctx, task); err != nil {
		return err
	}
	proof, err := psbt.NewFromRawBytes(strings.NewReader(task.Intent.Proof), true)
	if err != nil {
		return err
	}
	addr, err := s.getDelegateAddress(ctx)
	if err != nil {
		return err
	}
	feeScript, err := addr.GetPkScript()
	if err != nil {
		return err
	}
	count := 0
	for _, out := range proof.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, feeScript) {
			continue
		}
		if !bytes.Equal(out.PkScript, pkScript) || out.Value <= 0 {
			return fmt.Errorf("intent has unsupported replacement output")
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("intent must contain exactly one replacement output")
	}
	if err := r.Grant.Validate(s.recovery.Origin(), s.recovery.Public(), uint64(time.Now().Unix())); err != nil {
		return err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return err
	}
	task.RecoveryRegistration = string(encoded)
	return nil
}

func (s *DelegateService) recoveryInputs(ctx context.Context, task *domain.DelegateTask) error {
	points := make([]clientTypes.Outpoint, 0, len(task.Intent.Inputs))
	for _, p := range task.Intent.Inputs {
		points = append(points, clientTypes.Outpoint{Txid: p.Hash.String(), VOut: p.Index})
	}
	result, err := s.svc.Indexer().GetVtxos(ctx, indexer.WithOutpoints(points))
	if err != nil {
		return err
	}
	if len(result.Vtxos) != len(points) {
		return fmt.Errorf("missing recovery inputs")
	}
	seen := make(map[string]bool)
	for _, v := range result.Vtxos {
		id := v.Outpoint.String()
		if seen[id] || v.Spent || v.Unrolled || v.IsRecoverable() || len(v.Assets) > 0 {
			return fmt.Errorf("protected input is not a unique live BTC VTXO")
		}
		seen[id] = true
		found := false
		for p, raw := range task.ForfeitTxs {
			if p.String() != id {
				continue
			}
			found = true
			f, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
			if err != nil {
				return err
			}
			if len(f.Inputs) != 1 || f.Inputs[0].WitnessUtxo == nil {
				return fmt.Errorf("missing input witness")
			}
			actualScript, err := hex.DecodeString(v.Script)
			if err != nil {
				return err
			}
			if !bytes.Equal(f.Inputs[0].WitnessUtxo.PkScript, actualScript) || uint64(f.Inputs[0].WitnessUtxo.Value) != v.Amount {
				return fmt.Errorf("forfeit prevout differs from indexer")
			}
		}
		if !found {
			return fmt.Errorf("input has no authorized forfeit")
		}
	}
	return nil
}

type recoveryBundle struct {
	Version        int                   `json:"version"`
	Network        string                `json:"network"`
	BatchID        string                `json:"batch_id"`
	Commitment     string                `json:"commitment_psbt"`
	CommitmentTxID string                `json:"commitment_txid"`
	Registration   recovery.Registration `json:"registration"`
	Intent         domain.Intent         `json:"intent"`
	Replacement    string                `json:"replacement_outpoint"`
	Branch         []string              `json:"branch_psbts"`
	// Operator batch sweep path, including expiry units/value, for restoration.
	BatchSweepScript string `json:"batch_sweep_script"`
}

func (h *delegateBatchSessionHandler) backupBeforeForfeits(ctx context.Context, event client.BatchFinalizationEvent, t *tree.TxTree, ids []string) (map[string]string, error) {
	s := h.delegate
	if s.recovery == nil {
		return nil, nil
	}
	cfg, err := s.svc.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateRecoveryNetwork(cfg.Network.Name); err != nil {
		return nil, err
	}
	commit, err := psbt.NewFromRawBytes(strings.NewReader(event.Tx), true)
	if err != nil {
		return nil, err
	}
	sweep, err := h.SweepClosure.Script()
	if err != nil {
		return nil, err
	}
	// One total deadline, including serialized deliveries, for this callback.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	receipts := make(map[string]string, len(ids))
	for _, id := range ids {
		task, err := s.svc.dbSvc.Delegate().GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		r, err := recovery.ParseRegistration(task.RecoveryRegistration)
		if err != nil {
			return nil, fmt.Errorf("protected task lacks recovery registration")
		}
		if err = s.recoveryInputs(ctx, task); err != nil {
			return nil, err
		}
		proof, err := psbt.NewFromRawBytes(strings.NewReader(task.Intent.Proof), true)
		if err != nil {
			return nil, err
		}
		if len(r.Outputs) != 1 {
			return nil, fmt.Errorf("invalid stored recovery metadata")
		}
		expectedScript, err := hex.DecodeString(r.Outputs[0].Script)
		if err != nil {
			return nil, err
		}
		amount := int64(-1)
		for _, out := range proof.UnsignedTx.TxOut {
			if bytes.Equal(out.PkScript, expectedScript) {
				if amount >= 0 {
					return nil, fmt.Errorf("ambiguous expected output")
				}
				amount = out.Value
			}
		}
		branch, outpoint, err := recovery.ExtractBranch(t, commit, expectedScript, amount)
		if err != nil {
			return nil, err
		}
		bundle := recoveryBundle{Version: 1, Network: cfg.Network.Name, BatchID: event.Id, Commitment: event.Tx, CommitmentTxID: commit.UnsignedTx.TxID(), Registration: r, Intent: task.Intent, Replacement: outpoint, Branch: branch, BatchSweepScript: hex.EncodeToString(sweep)}
		plain, err := json.Marshal(bundle)
		if err != nil {
			return nil, err
		}
		receipt, err := s.recovery.DeliverReceipt(ctx, task.Intent.Txid, event.Id, r, plain)
		if err != nil {
			return nil, fmt.Errorf("recovery gate: %w", err)
		}
		receipts[id] = receipt.Hash
		log.WithFields(log.Fields{"batch": event.Id, "commitment": commit.UnsignedTx.TxID(), "task": id, "ciphertext": receipt.Hash}).Info("recovery backup acknowledged")
	}
	return receipts, nil
}
