package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

type AttemptPhase string

const maxAttemptStorageBytes int64 = 32 * 1024 * 1024
const maxAttemptTaskReferences = 10000

const (
	AttemptPreparing         AttemptPhase = "preparing"
	AttemptAcknowledged      AttemptPhase = "acknowledged"
	AttemptSubmissionUnknown AttemptPhase = "submission_unknown"
	AttemptSubmitted         AttemptPhase = "submitted"
	AttemptFinalized         AttemptPhase = "finalized"
)

// ProtectedAttempt records local observations, never an inference from absent
// chain data. The candidate and task set cannot change after the first fsync.
// Retain this alongside the task database and encrypted outboxes on restoration.
type ProtectedAttempt struct {
	Version          int               `json:"version"`
	BatchID          string            `json:"batch_id"`
	CommitmentTxID   string            `json:"commitment_txid"`
	CandidatePSBT    string            `json:"candidate_psbt"`
	TaskIDs          []string          `json:"task_ids"`
	Receipts         map[string]string `json:"receipts,omitempty"`
	Phase            AttemptPhase      `json:"phase"`
	QuarantineReason string            `json:"quarantine_reason,omitempty"`
}

type signedAttempt struct {
	Attempt   ProtectedAttempt `json:"attempt"`
	Signature string           `json:"signature"`
}

func (a ProtectedAttempt) digest() []byte {
	raw, _ := json.Marshal(a)
	return Digest(Domain, "protected-attempt-v1", string(raw))
}

func (a ProtectedAttempt) validate() error {
	if a.Version != 1 || a.BatchID == "" || len(a.BatchID) > 128 || strings.ContainsRune(a.BatchID, 0) ||
		len(a.CandidatePSBT) > 512*1024 || len(a.TaskIDs) == 0 || len(a.TaskIDs) > 512 ||
		!slices.IsSorted(a.TaskIDs) || len(a.QuarantineReason) > 1024 {
		return errors.New("invalid protected attempt")
	}
	for i, id := range a.TaskIDs {
		if id == "" || len(id) > 128 || strings.ContainsRune(id, 0) || (i > 0 && id == a.TaskIDs[i-1]) {
			return errors.New("invalid protected task set")
		}
	}
	p, err := psbt.NewFromRawBytes(strings.NewReader(a.CandidatePSBT), true)
	if err != nil || p.UnsignedTx.TxID() != a.CommitmentTxID {
		return errors.New("protected candidate commitment mismatch")
	}
	switch a.Phase {
	case AttemptPreparing:
		if len(a.Receipts) != 0 {
			return errors.New("preparing attempt has receipts")
		}
	case AttemptAcknowledged, AttemptSubmissionUnknown, AttemptSubmitted, AttemptFinalized:
		if len(a.Receipts) != len(a.TaskIDs) {
			return errors.New("incomplete protected receipts")
		}
		for _, id := range a.TaskIDs {
			hash, err := hex.DecodeString(a.Receipts[id])
			if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != a.Receipts[id] {
				return errors.New("invalid protected receipt hash")
			}
		}
	default:
		return errors.New("unsupported protected attempt phase")
	}
	return nil
}

func (m *Manager) attemptPath(batchID string) string {
	return filepath.Join(m.dir, "attempt-"+hex.EncodeToString(Digest(batchID))+".json")
}

func (m *Manager) readAttempt(path string) (ProtectedAttempt, int64, error) {
	var saved signedAttempt
	f, err := os.Open(path)
	if err != nil {
		return saved.Attempt, 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return saved.Attempt, 0, err
	}
	if len(raw) > 1024*1024 {
		return saved.Attempt, 0, errors.New("protected attempt too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&saved); err != nil {
		return saved.Attempt, 0, err
	}
	if d.Decode(new(any)) != io.EOF {
		return saved.Attempt, 0, errors.New("trailing protected attempt data")
	}
	if err = saved.Attempt.validate(); err != nil {
		return saved.Attempt, 0, err
	}
	if path != m.attemptPath(saved.Attempt.BatchID) {
		return saved.Attempt, 0, errors.New("protected attempt filename mismatch")
	}
	if err = Verify(m.Public(), saved.Attempt.digest(), saved.Signature); err != nil {
		return saved.Attempt, 0, fmt.Errorf("protected attempt signature: %w", err)
	}
	return saved.Attempt, int64(len(raw)), nil
}

// SaveAttempt allows only forward observations for the exact same candidate.
// A quarantine is sticky: manual evidence review must not be an implicit retry.
func (m *Manager) SaveAttempt(ctx context.Context, a ProtectedAttempt) error {
	return m.saveAttempt(ctx, a, false)
}

// BeginAttempt is an exclusive claim: another handler/process cannot resume a
// retained candidate by overwriting the same preparing phase.
func (m *Manager) BeginAttempt(ctx context.Context, a ProtectedAttempt) error {
	return m.saveAttempt(ctx, a, true)
}

func (m *Manager) saveAttempt(ctx context.Context, a ProtectedAttempt, create bool) error {
	if err := m.acquire(ctx); err != nil {
		return err
	}
	defer m.release()
	if err := a.validate(); err != nil {
		return err
	}
	path := m.attemptPath(a.BatchID)
	previous, _, err := m.readAttempt(path)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return errors.New("protected attempt missing")
		}
		if a.Phase != AttemptPreparing {
			return errors.New("protected attempt must start before backup")
		}
		all, err := m.attempts(ctx)
		if err != nil {
			return err
		}
		if len(all) >= 10000 {
			return errors.New("protected attempt retention limit reached")
		}
		tasks := len(a.TaskIDs)
		for _, old := range all {
			if err := ctx.Err(); err != nil {
				return err
			}
			tasks += len(old.TaskIDs)
			if tasks > maxAttemptTaskReferences {
				return errors.New("protected task reference limit reached")
			}
			for _, id := range a.TaskIDs {
				if err := ctx.Err(); err != nil {
					return err
				}
				if slices.Contains(old.TaskIDs, id) {
					return errors.New("task already belongs to a retained protected attempt")
				}
			}
		}
	} else if err != nil {
		return err
	} else {
		if create {
			return errors.New("protected attempt already retained; reconciliation required")
		}
		if previous.CandidatePSBT != a.CandidatePSBT || previous.CommitmentTxID != a.CommitmentTxID || !slices.Equal(previous.TaskIDs, a.TaskIDs) {
			return errors.New("protected candidate changed")
		}
		oldReceipts, _ := json.Marshal(previous.Receipts)
		newReceipts, _ := json.Marshal(a.Receipts)
		if previous.Phase != AttemptPreparing && !bytes.Equal(oldReceipts, newReceipts) {
			return errors.New("protected receipts changed")
		}
		allowed := previous.Phase == a.Phase ||
			(previous.Phase == AttemptPreparing && a.Phase == AttemptAcknowledged) ||
			(previous.Phase == AttemptAcknowledged && a.Phase == AttemptSubmissionUnknown) ||
			(previous.Phase == AttemptSubmissionUnknown && (a.Phase == AttemptSubmitted || a.Phase == AttemptFinalized)) ||
			(previous.Phase == AttemptSubmitted && a.Phase == AttemptFinalized)
		if !allowed || (previous.QuarantineReason != "" && (previous.QuarantineReason != a.QuarantineReason || previous.Phase != a.Phase)) {
			return errors.New("protected attempt cannot regress or leave quarantine")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	signature, err := Sign(m.key, a.digest())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(signedAttempt{Attempt: a, Signature: signature})
	if err != nil {
		return err
	}
	if err := m.attemptCapacity(ctx, path, int64(len(raw))); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return atomicWrite(path, raw)
}

// Check byte admission without retaining any candidate contents. Updating a
// record replaces its prior size; previously admitted evidence is never removed.
func (m *Manager) attemptCapacity(ctx context.Context, replace string, size int64) error {
	paths, err := filepath.Glob(filepath.Join(m.dir, "attempt-*.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == replace {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		size += info.Size()
		if size > maxAttemptStorageBytes {
			return errors.New("protected attempt byte limit reached; reconcile retained storage")
		}
	}
	if size > maxAttemptStorageBytes {
		return errors.New("protected attempt byte limit reached")
	}
	return nil
}

func (m *Manager) attempts(ctx context.Context) ([]ProtectedAttempt, error) {
	paths, err := filepath.Glob(filepath.Join(m.dir, "attempt-*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) > 10000 {
		return nil, errors.New("protected attempt retention limit reached; reconcile storage")
	}
	result := make([]ProtectedAttempt, 0, len(paths))
	seen := make(map[string]bool)
	var size int64
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a, serializedSize, err := m.readAttempt(path)
		size += serializedSize
		if size > maxAttemptStorageBytes {
			return nil, errors.New("protected attempt byte limit reached; reconcile retained storage")
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read retained protected attempt: %w", err)
		}
		for _, id := range a.TaskIDs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if seen[id] {
				return nil, errors.New("task occurs in multiple protected attempts")
			}
			seen[id] = true
			if len(seen) > maxAttemptTaskReferences {
				return nil, errors.New("protected task reference limit reached")
			}
		}
		result = append(result, a)
	}
	return result, nil
}

func (m *Manager) Attempts(ctx context.Context) ([]ProtectedAttempt, error) {
	if err := m.acquire(ctx); err != nil {
		return nil, err
	}
	defer m.release()
	return m.attempts(ctx)
}

// RetainedOutboxGrants detects historical pending tasks whose old binary could
// have submitted forfeits without a durable attempt. Such absence is not retry permission.
func (m *Manager) RetainedOutboxGrants(ctx context.Context) (map[string]bool, error) {
	if err := m.acquire(ctx); err != nil {
		return nil, err
	}
	defer m.release()
	paths, err := filepath.Glob(filepath.Join(m.dir, "outbox-*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) > 10000 {
		return nil, errors.New("outbox inspection limit reached")
	}
	grants := make(map[string]bool)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := readOutbox(path)
		if err != nil {
			return nil, err
		}
		var b outbox
		if err = json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if b.IntentID == "" || b.BatchID == "" {
			return nil, errors.New("legacy outbox association unavailable; preserve and reconcile before scheduling protected tasks")
		}
		if path != filepath.Join(m.dir, "outbox-"+hex.EncodeToString(Digest(b.IntentID, b.BatchID))+".json") {
			return nil, errors.New("retained outbox filename association mismatch")
		}
		if err := m.authenticateOutbox(b, b.IntentID, b.BatchID); err != nil {
			return nil, err
		}
		grants[b.Request.Grant.ID] = true
	}
	return grants, nil
}
