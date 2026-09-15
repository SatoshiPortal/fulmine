package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func testAttempt(t *testing.T) ProtectedAttempt {
	t.Helper()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(wire.NewTxOut(100, []byte{0x51}))
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	raw, err := p.B64Encode()
	require.NoError(t, err)
	return ProtectedAttempt{Version: 1, BatchID: "batch", CommitmentTxID: tx.TxID(), CandidatePSBT: raw,
		TaskIDs: []string{"a", "b"}, Phase: AttemptPreparing}
}

func TestProtectedAttemptPersistenceAndTampering(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "http://127.0.0.1:9081")
	require.NoError(t, err)
	a := testAttempt(t)
	require.NoError(t, m.BeginAttempt(t.Context(), a))
	require.Error(t, m.BeginAttempt(t.Context(), a))
	a.Receipts = map[string]string{"a": strings.Repeat("a", 64), "b": strings.Repeat("b", 64)}
	a.Phase = AttemptAcknowledged
	require.NoError(t, m.SaveAttempt(t.Context(), a))
	a.Phase = AttemptSubmissionUnknown
	require.NoError(t, m.SaveAttempt(t.Context(), a))
	require.NoError(t, m.Close())
	m, err = NewManager(dir, "http://127.0.0.1:9081")
	require.NoError(t, err)
	defer m.Close()
	restored, err := m.Attempts(t.Context())
	require.NoError(t, err)
	require.Equal(t, []ProtectedAttempt{a}, restored)
	changed := a
	changed.Phase = AttemptPreparing
	changed.Receipts = nil
	require.Error(t, m.SaveAttempt(t.Context(), changed))
	changed = a
	changed.TaskIDs = []string{"a", "c"}
	require.Error(t, m.SaveAttempt(t.Context(), changed))
	changed = a
	changed.Phase = AttemptFinalized
	require.NoError(t, m.SaveAttempt(t.Context(), changed)) // matching final event may resolve a lost response
	changed.QuarantineReason = "operator review required"
	require.NoError(t, m.SaveAttempt(t.Context(), changed))
	changed.QuarantineReason = ""
	require.Error(t, m.SaveAttempt(t.Context(), changed))
	path := m.attemptPath(a.BatchID)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var saved signedAttempt
	require.NoError(t, json.Unmarshal(raw, &saved))
	saved.Attempt.QuarantineReason = "tampered"
	raw, err = json.Marshal(saved)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	_, err = m.Attempts(t.Context())
	require.ErrorContains(t, err, "signature")
	require.Error(t, m.BeginAttempt(t.Context(), testAttempt(t)))
}

func TestProtectedAttemptClaimAndStorageFailure(t *testing.T) {
	m, err := NewManager(t.TempDir(), "http://127.0.0.1:9081")
	require.NoError(t, err)
	defer m.Close()
	a := testAttempt(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if m.BeginAttempt(context.Background(), a) == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	other := a
	other.BatchID = "another-batch"
	require.ErrorContains(t, m.BeginAttempt(t.Context(), other), "already belongs")
	other.TaskIDs = []string{"c"}
	require.NoError(t, os.Mkdir(m.attemptPath(other.BatchID), 0700))
	require.Error(t, m.BeginAttempt(t.Context(), other))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, m.SaveAttempt(ctx, a), context.Canceled)
}

func TestProtectedAttemptCumulativeByteLimit(t *testing.T) {
	m, err := NewManager(t.TempDir(), "http://127.0.0.1:9081")
	require.NoError(t, err)
	defer m.Close()
	for i := 0; i < 33; i++ {
		a := testAttempt(t)
		a.BatchID = fmt.Sprintf("batch-%02d", i)
		a.TaskIDs = []string{fmt.Sprintf("task-%02d", i)}
		sig, err := Sign(m.key, a.digest())
		require.NoError(t, err)
		raw, err := json.Marshal(signedAttempt{Attempt: a, Signature: sig})
		require.NoError(t, err)
		// Individually readable, correctly signed records from an oversized
		// restored directory must not accumulate gigabytes of candidate data.
		raw = append([]byte(strings.Repeat(" ", 1024*1024-len(raw))), raw...)
		require.NoError(t, os.WriteFile(m.attemptPath(a.BatchID), raw, 0600))
	}
	_, err = m.Attempts(t.Context())
	require.ErrorContains(t, err, "byte limit")
	require.ErrorContains(t, m.attemptCapacity(t.Context(), "", 1), "byte limit")
	require.Error(t, m.BeginAttempt(t.Context(), testAttempt(t)))
}

// Cancel after acquire's first Err check, exercising cancellation while the
// manager owns its lock rather than only cancellation before entry.
type cancelAfterAcquire struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAfterAcquire) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestProtectedAttemptCancellationAfterAcquire(t *testing.T) {
	m, err := NewManager(t.TempDir(), "http://127.0.0.1:9081")
	require.NoError(t, err)
	defer m.Close()
	a := testAttempt(t)
	require.NoError(t, m.BeginAttempt(t.Context(), a))
	for _, operation := range []string{"scan", "write"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			controlled := &cancelAfterAcquire{Context: ctx, cancel: cancel}
			if operation == "scan" {
				_, err = m.Attempts(controlled)
			} else {
				changed := a
				changed.QuarantineReason = "must not persist after cancellation"
				err = m.SaveAttempt(controlled, changed)
			}
			require.ErrorIs(t, err, context.Canceled)
			after, err := m.Attempts(t.Context())
			require.NoError(t, err)
			require.Equal(t, []ProtectedAttempt{a}, after)
		})
	}
}
