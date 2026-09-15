package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/fulmine/internal/core/domain"
	"github.com/ArkLabsHQ/fulmine/internal/core/ports"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type gateRepository struct {
	domain.DelegateRepository
	failed, completed    int
	failErr, completeErr error
}

func TestRecoveryNetworkBoundary(t *testing.T) {
	for _, network := range []string{"regtest", "mutinynet"} {
		t.Run(network, func(t *testing.T) {
			require.NoError(t, validateRecoveryNetwork(network))
		})
	}
	for _, network := range []string{"bitcoin", "mainnet", "signet", "testnet", "", "Mutinynet", "mutinynet "} {
		t.Run("reject_"+network, func(t *testing.T) {
			require.Error(t, validateRecoveryNetwork(network))
		})
	}
}

func (r *gateRepository) FailTasks(context.Context, string, ...string) error {
	r.failed++
	return r.failErr
}
func (r *gateRepository) CompleteTasks(context.Context, string, ...string) error {
	r.completed++
	return r.completeErr
}

type gateRepos struct {
	ports.RepoManager
	repo *gateRepository
}

func (r gateRepos) Delegate() domain.DelegateRepository { return r.repo }
func gateHandler(t *testing.T) (*delegateBatchSessionHandler, *gateRepository) {
	r := &gateRepository{}
	m, err := recovery.NewManager(t.TempDir(), "http://127.0.0.1:9081")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return &delegateBatchSessionHandler{delegate: &DelegateService{svc: &Service{dbSvc: gateRepos{repo: r}}, recovery: m, registeredIntents: map[string]registeredIntent{}}, selectedTasks: []registeredIntent{{taskID: "task"}}}, r
}
func gateEvent(t *testing.T) client.BatchFinalizationEvent {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(wire.NewTxOut(100, []byte{0x51}))
	p, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	raw, err := p.B64Encode()
	require.NoError(t, err)
	return client.BatchFinalizationEvent{Id: "batch", Tx: raw}
}
func gateReceipt() (map[string]string, error) {
	return map[string]string{"task": strings.Repeat("a", 64)}, nil
}

func TestRecoveryGateOrdersAndBindsCandidate(t *testing.T) {
	h, r := gateHandler(t)
	event := gateEvent(t)
	order := []string{}
	backup := func() (map[string]string, error) { order = append(order, "ack"); return gateReceipt() }
	submit := func() error { order = append(order, "forfeit"); return nil }
	require.NoError(t, h.finalizeRecovery(context.Background(), event, backup, submit))
	require.NoError(t, h.finalizeRecovery(context.Background(), event, backup, submit))
	require.Equal(t, []string{"ack", "forfeit"}, order)
	require.Equal(t, strings.Repeat("a", 64), h.recoveryAttempt.receipts["task"])
	require.Error(t, h.OnBatchFinalized(context.Background(), client.BatchFinalizedEvent{Id: event.Id, Txid: strings.Repeat("b", 64)}))
	require.Zero(t, r.completed)
	require.Error(t, h.finalizeRecovery(context.Background(), event, backup, submit))
	require.Len(t, order, 2)
}
func TestRecoveryGateRejectsFailuresBeforeSubmission(t *testing.T) {
	for _, mode := range []string{"timeout", "missing receipt", "changed candidate", "changed tasks", "task update failure"} {
		t.Run(mode, func(t *testing.T) {
			h, r := gateHandler(t)
			e := gateEvent(t)
			calls := 0
			backup := gateReceipt
			switch mode {
			case "timeout":
				backup = func() (map[string]string, error) { return nil, context.DeadlineExceeded }
			case "missing receipt":
				backup = func() (map[string]string, error) { return map[string]string{}, nil }
			case "task update failure":
				r.failErr = errors.New("disk unavailable")
				backup = func() (map[string]string, error) { return nil, errors.New("backup failed") }
			default:
				require.NoError(t, h.finalizeRecovery(context.Background(), e, backup, func() error { return nil }))
				if mode == "changed candidate" {
					e.Id = "different"
				} else {
					h.selectedTasks = append(h.selectedTasks, registeredIntent{taskID: "other"})
				}
			}
			require.Error(t, h.finalizeRecovery(context.Background(), e, backup, func() error { calls++; return nil }))
			require.Zero(t, calls)
			require.Equal(t, recoveryFailed, h.recoveryAttempt.phase)
			require.Error(t, h.finalizeRecovery(context.Background(), e, gateReceipt, func() error { calls++; return nil }))
			require.Zero(t, calls)
		})
	}
}
func TestRecoveryGateMissingConnectors(t *testing.T) {
	h, r := gateHandler(t)
	require.Error(t, h.OnBatchFinalization(context.Background(), gateEvent(t), nil, nil))
	require.Equal(t, 1, r.failed)
	require.Equal(t, recoveryFailed, h.recoveryAttempt.phase)
}
func TestRecoverySubmissionLostResponse(t *testing.T) {
	h, r := gateHandler(t)
	e := gateEvent(t)
	calls := 0
	submit := func() error { calls++; return errors.New("response lost") }
	require.Error(t, h.finalizeRecovery(context.Background(), e, gateReceipt, submit))
	require.Equal(t, recoverySubmissionUnknown, h.recoveryAttempt.phase)
	require.Error(t, h.finalizeRecovery(context.Background(), e, gateReceipt, submit))
	require.Equal(t, 1, calls)
	require.Zero(t, r.failed)
	// A matching finalized event resolves an uncertain transport outcome.
	r.completeErr = errors.New("database unavailable")
	done := client.BatchFinalizedEvent{Id: e.Id, Txid: h.recoveryAttempt.txid}
	require.Error(t, h.OnBatchFinalized(context.Background(), done))
	r.completeErr = nil
	require.NoError(t, h.OnBatchFinalized(context.Background(), done))
	require.Equal(t, 2, r.completed)
}
func TestRecoveryGateBatchFailureRevokesReadiness(t *testing.T) {
	h, r := gateHandler(t)
	e := gateEvent(t)
	require.NoError(t, h.finalizeRecovery(context.Background(), e, gateReceipt, func() error { return nil }))
	require.Error(t, h.OnBatchFailed(context.Background(), client.BatchFailedEvent{Id: e.Id}))
	require.Error(t, h.OnBatchFinalized(context.Background(), client.BatchFinalizedEvent{Id: e.Id, Txid: h.recoveryAttempt.txid}))
	require.Zero(t, r.completed)
}
func TestRecoveryDisabledCompletion(t *testing.T) {
	h, r := gateHandler(t)
	h.delegate.recovery = nil
	require.NoError(t, h.OnBatchFinalized(context.Background(), client.BatchFinalizedEvent{Id: "batch", Txid: "original-behavior"}))
	require.Equal(t, 1, r.completed)
}
