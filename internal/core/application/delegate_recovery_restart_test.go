package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArkLabsHQ/fulmine/internal/core/domain"
	"github.com/ArkLabsHQ/fulmine/internal/core/ports"
	"github.com/ArkLabsHQ/fulmine/internal/infrastructure/db"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type restartScheduler struct {
	ports.SchedulerService
	calls int
}

func (s *restartScheduler) ScheduleTaskAtTime(time.Time, func()) error { s.calls++; return nil }

type crashCompleteRepo struct{ domain.DelegateRepository }

func (r crashCompleteRepo) CompleteTasks(context.Context, string, ...string) error {
	os.Exit(67)
	return nil
}

type restartRepos struct {
	ports.RepoManager
	delegate domain.DelegateRepository
}

func (r restartRepos) Delegate() domain.DelegateRepository { return r.delegate }

func restartDB(t *testing.T, root, backend string) ports.RepoManager {
	t.Helper()
	cfg := db.ServiceConfig{DbType: backend, DbConfig: []any{filepath.Join(root, "tasks")}}
	if backend == "badger" {
		cfg.DbConfig = append(cfg.DbConfig, nil)
	}
	repo, err := db.NewService(cfg)
	require.NoError(t, err)
	return repo
}

func gateTxid(t *testing.T, encoded string) string {
	t.Helper()
	p, err := psbt.NewFromRawBytes(strings.NewReader(encoded), true)
	require.NoError(t, err)
	return p.UnsignedTx.TxID()
}

func crashProtectedAttempt(t *testing.T, root, backend, boundary string) {
	repo := restartDB(t, root, backend)
	origin := "http://127.0.0.1:9081"
	var server *httptest.Server
	if boundary == "remote_ack" {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request recovery.StoreRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(recovery.Receipt{ID: 1, Hash: request.Hash})
		}))
		origin = server.URL
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "origin"), []byte(origin), 0600))
	m, err := recovery.NewManager(filepath.Join(root, "recovery"), origin)
	require.NoError(t, err)
	owner, _ := btcec.PrivKeyFromBytes([]byte{1})
	g := recovery.Grant{Owner: recovery.Public(owner), Publisher: m.Public(), Origin: origin,
		ID: strings.Repeat("1", 64), Scope: strings.Repeat("2", 64), ValidFrom: uint64(time.Now().Unix() - 1),
		ExpiresAt: uint64(time.Now().Unix() + 3600), MaxRecords: 1, MaxBytes: 128 * 1024}
	g.Signature, err = recovery.Sign(owner, g.Digest())
	require.NoError(t, err)
	r := recovery.Registration{Grant: g}
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	task := domain.DelegateTask{ID: "task", Intent: domain.Intent{Txid: strings.Repeat("3", 64), Inputs: []wire.OutPoint{{Index: 1}}},
		RecoveryRegistration: string(raw), ScheduledAt: time.Now(), Status: domain.DelegateTaskStatusPending}
	require.NoError(t, repo.Delegate().Add(t.Context(), task))
	s := &DelegateService{svc: &Service{dbSvc: repo}, recovery: m, registeredIntents: map[string]registeredIntent{}}
	h := &delegateBatchSessionHandler{delegate: s, selectedTasks: []registeredIntent{{taskID: task.ID}}}
	event := gateEvent(t)
	backup := func() (map[string]string, error) {
		if boundary == "pre_upload" {
			os.Exit(67)
		}
		if boundary == "remote_ack" {
			_, err := m.DeliverReceipt(t.Context(), task.ID, event.Id, r, []byte("public crash-test candidate"))
			require.NoError(t, err)
			os.Exit(67) // remote reply and local outbox persisted, handler has not saved ACK phase
		}
		return gateReceipt()
	}
	if boundary == "acknowledged" {
		// Crash directly after the real journal transition. The gate test below
		// separately checks that these writes bracket its actual I/O callbacks.
		a := recovery.ProtectedAttempt{Version: 1, BatchID: event.Id, CommitmentTxID: gateTxid(t, event.Tx), CandidatePSBT: event.Tx,
			TaskIDs: []string{task.ID}, Phase: recovery.AttemptPreparing}
		require.NoError(t, m.BeginAttempt(t.Context(), a))
		a.Phase = recovery.AttemptAcknowledged
		a.Receipts, _ = gateReceipt()
		require.NoError(t, m.SaveAttempt(t.Context(), a))
		os.Exit(67)
	}
	err = h.finalizeRecovery(t.Context(), event, backup, func() error {
		attempts, err := m.Attempts(t.Context())
		require.NoError(t, err)
		require.Equal(t, recovery.AttemptSubmissionUnknown, attempts[0].Phase)
		if boundary == "submission_unknown" {
			os.Exit(67)
		}
		require.NoError(t, os.WriteFile(filepath.Join(root, "forfeit-submission"), []byte("once"), 0600))
		if boundary == "lost_response" {
			return errors.New("submission response lost")
		}
		return nil
	})
	if boundary == "lost_response" {
		require.Error(t, err)
		os.Exit(67)
	}
	require.NoError(t, err)
	if boundary == "finalized" {
		s.svc.dbSvc = restartRepos{RepoManager: repo, delegate: crashCompleteRepo{repo.Delegate()}}
		require.NoError(t, h.OnBatchFinalized(t.Context(), client.BatchFinalizedEvent{Id: event.Id, Txid: h.recoveryAttempt.txid}))
		t.Fatal("completion crash was not reached")
	}
	os.Exit(67)
}

func TestProtectedAttemptCrashProcess(t *testing.T) {
	if root := os.Getenv("FULMINE_RESTART_CHILD_DIR"); root != "" {
		crashProtectedAttempt(t, root, os.Getenv("FULMINE_RESTART_BACKEND"), os.Getenv("FULMINE_RESTART_BOUNDARY"))
		return
	}
	for _, backend := range []string{"sqlite", "badger"} {
		for _, boundary := range []string{"pre_upload", "remote_ack", "acknowledged", "submission_unknown", "lost_response", "submitted", "finalized"} {
			t.Run(backend+"/"+boundary, func(t *testing.T) {
				root := t.TempDir()
				executable, err := os.Executable()
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestProtectedAttemptCrashProcess$", "-test.count=1")
				cmd.Env = append(os.Environ(), "FULMINE_RESTART_CHILD_DIR="+root, "FULMINE_RESTART_BACKEND="+backend, "FULMINE_RESTART_BOUNDARY="+boundary)
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				require.ErrorAs(t, err, &exit, string(output))
				require.Equal(t, 67, exit.ExitCode(), string(output))
				repo := restartDB(t, root, backend)
				defer repo.Close()
				origin, err := os.ReadFile(filepath.Join(root, "origin"))
				require.NoError(t, err)
				m, err := recovery.NewManager(filepath.Join(root, "recovery"), string(origin))
				require.NoError(t, err)
				defer m.Close()
				scheduler := &restartScheduler{}
				s := &DelegateService{svc: &Service{dbSvc: repo, schedulerSvc: scheduler}, recovery: m, ctx: t.Context(), registeredIntents: map[string]registeredIntent{}}
				require.NoError(t, s.restorePendingTasks())
				require.Zero(t, scheduler.calls)
				task, err := repo.Delegate().GetByID(t.Context(), "task")
				require.NoError(t, err)
				attempts, err := m.Attempts(t.Context())
				require.NoError(t, err)
				require.Len(t, attempts, 1)
				phases := map[string]recovery.AttemptPhase{
					"pre_upload": recovery.AttemptPreparing, "remote_ack": recovery.AttemptPreparing,
					"acknowledged": recovery.AttemptAcknowledged, "submission_unknown": recovery.AttemptSubmissionUnknown,
					"lost_response": recovery.AttemptSubmissionUnknown, "submitted": recovery.AttemptSubmitted,
					"finalized": recovery.AttemptFinalized,
				}
				require.Equal(t, phases[boundary], attempts[0].Phase)
				require.Equal(t, gateEvent(t).Tx, attempts[0].CandidatePSBT)
				if attempts[0].Phase != recovery.AttemptPreparing {
					require.Equal(t, strings.Repeat("a", 64), attempts[0].Receipts[task.ID])
				}
				if boundary == "finalized" {
					require.Equal(t, domain.DelegateTaskStatusCompleted, task.Status)
					require.Equal(t, attempts[0].CommitmentTxID, task.CommitmentTxid)
				} else {
					require.Equal(t, domain.DelegateTaskStatusFailed, task.Status)
					require.Contains(t, task.FailReason, protectedQuarantinePrefix)
					require.Contains(t, task.FailReason, attempts[0].CommitmentTxID)
					require.NotEmpty(t, attempts[0].QuarantineReason)
				}
				// A different intent and allowReplace must not bypass input quarantine.
				require.Error(t, s.checkProtectedOverlap(t.Context(), task.Intent.Inputs))
				require.NoError(t, s.checkProtectedOverlap(t.Context(), []wire.OutPoint{{Index: 999}}))
				require.NoError(t, s.registerDelegate(task.ID)) // terminal task never reaches Ark
				calls := 0
				h := &delegateBatchSessionHandler{delegate: s, selectedTasks: []registeredIntent{{taskID: task.ID}}}
				require.Error(t, h.finalizeRecovery(t.Context(), gateEvent(t), func() (map[string]string, error) { calls++; return gateReceipt() }, func() error { calls++; return nil }))
				require.Zero(t, calls)
				unrelated := domain.DelegateTask{ID: "unrelated", Intent: domain.Intent{Txid: strings.Repeat("4", 64), Inputs: []wire.OutPoint{{Index: 999}}}, Status: domain.DelegateTaskStatusPending, ScheduledAt: time.Now()}
				require.NoError(t, repo.Delegate().Add(t.Context(), unrelated))
				cancelIDs, err := s.cancellableUnprotectedTasks(t.Context(), []string{"task", "unrelated"})
				require.NoError(t, err)
				require.Equal(t, []string{"unrelated"}, cancelIDs)
			})
		}
	}
}

func TestProtectedRecoveryLegacyAndUnavailableStorage(t *testing.T) {
	for _, mode := range []string{"legacy", "corrupt", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			repo := restartDB(t, root, "sqlite")
			defer repo.Close()
			dir := filepath.Join(root, "recovery")
			m, err := recovery.NewManager(dir, "http://127.0.0.1:9081")
			require.NoError(t, err)
			defer m.Close()
			r := recovery.Registration{Grant: recovery.Grant{ID: strings.Repeat("1", 64)}}
			raw, err := json.Marshal(r)
			require.NoError(t, err)
			task := domain.DelegateTask{ID: "task", Intent: domain.Intent{Txid: strings.Repeat("3", 64), Inputs: []wire.OutPoint{{Index: 1}}}, RecoveryRegistration: string(raw), Status: domain.DelegateTaskStatusPending, ScheduledAt: time.Now()}
			require.NoError(t, repo.Delegate().Add(t.Context(), task))
			scheduler := &restartScheduler{}
			s := &DelegateService{svc: &Service{dbSvc: repo, schedulerSvc: scheduler}, recovery: m, ctx: t.Context()}
			switch mode {
			case "legacy":
				raw, err = json.Marshal(map[string]any{"request": recovery.StoreRequest{Grant: r.Grant}})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "outbox-legacy.json"), raw, 0600))
				ids, err := s.cancellableUnprotectedTasks(t.Context(), []string{task.ID})
				require.Error(t, err)
				require.Empty(t, ids)
			case "corrupt":
				require.NoError(t, os.WriteFile(filepath.Join(dir, "attempt-corrupt.json"), []byte("{}"), 0600))
			case "disabled":
				s.recovery = nil
			}
			require.NoError(t, s.restorePendingTasks())
			require.Zero(t, scheduler.calls)
			stored, err := repo.Delegate().GetByID(t.Context(), task.ID)
			require.NoError(t, err)
			require.Equal(t, domain.DelegateTaskStatusFailed, stored.Status)
			require.Contains(t, stored.FailReason, protectedQuarantinePrefix)
			require.Error(t, s.checkProtectedOverlap(t.Context(), task.Intent.Inputs))
		})
	}
}

func TestProtectedGatePersistenceFailurePreventsSubmission(t *testing.T) {
	h, _ := gateHandler(t)
	calls := 0
	err := h.finalizeRecovery(t.Context(), gateEvent(t), func() (map[string]string, error) {
		attempts, err := h.delegate.recovery.Attempts(t.Context())
		require.NoError(t, err)
		require.Equal(t, recovery.AttemptPreparing, attempts[0].Phase)
		require.NoError(t, h.delegate.recovery.Close())
		return gateReceipt()
	}, func() error { calls++; return nil })
	require.Error(t, err)
	require.Zero(t, calls)
}

func TestProtectedActiveRetryDoesNotQuarantineRunningAttempt(t *testing.T) {
	h, repo := gateHandler(t)
	e := gateEvent(t)
	require.NoError(t, h.finalizeRecovery(t.Context(), e, gateReceipt, func() error { return nil }))
	task := &domain.DelegateTask{ID: "task", RecoveryRegistration: "{}"}
	handled, err := h.delegate.restoreProtectedTask(t.Context(), task, false)
	require.True(t, handled)
	require.Error(t, err)
	require.Zero(t, repo.failed)
	attempts, err := h.delegate.recovery.Attempts(t.Context())
	require.NoError(t, err)
	require.Empty(t, attempts[0].QuarantineReason)
	require.Equal(t, recovery.AttemptSubmitted, attempts[0].Phase)
	require.NoError(t, h.OnBatchFinalized(t.Context(), client.BatchFinalizedEvent{Id: e.Id, Txid: h.recoveryAttempt.txid}))
}

type recoveryNetworkWallet struct {
	arksdk.Wallet
	network string
}

func (w recoveryNetworkWallet) GetConfigData(context.Context) (*clientTypes.Config, error) {
	return &clientTypes.Config{Network: arklib.Network{Name: w.network}}, nil
}

func TestProtectedRegistrationNetworkGate(t *testing.T) {
	for _, network := range []string{"regtest", "mutinynet", "bitcoin", "mainnet"} {
		t.Run(network, func(t *testing.T) {
			repo := restartDB(t, t.TempDir(), "sqlite")
			defer repo.Close()
			task := domain.DelegateTask{ID: "task", Intent: domain.Intent{Txid: strings.Repeat("3", 64), Inputs: []wire.OutPoint{{Index: 1}}}, RecoveryRegistration: "{}", Status: domain.DelegateTaskStatusPending, ScheduledAt: time.Now()}
			require.NoError(t, repo.Delegate().Add(t.Context(), task))
			m, err := recovery.NewManager(t.TempDir(), "http://127.0.0.1:9081")
			require.NoError(t, err)
			defer m.Close()
			s := &DelegateService{svc: &Service{dbSvc: repo, Wallet: recoveryNetworkWallet{network: network}}, recovery: m, ctx: t.Context()}
			err = s.registerDelegate(task.ID)
			if network == "regtest" || network == "mutinynet" {
				// A deliberately invalid grant stops before any real Ark call. Reaching
				// this gate proves the actual registration path accepted the network.
				require.ErrorContains(t, err, "invalid or expired recovery grant")
			} else {
				require.ErrorContains(t, err, "supports regtest and mutinynet only")
			}
		})
	}
}

func TestProtectedStreamTerminationPreservesUncertainty(t *testing.T) {
	for _, finalized := range []bool{false, true} {
		t.Run(fmt.Sprint(finalized), func(t *testing.T) {
			h, repo := gateHandler(t)
			e := gateEvent(t)
			require.Error(t, h.finalizeRecovery(t.Context(), e, gateReceipt, func() error { return errors.New("response lost") }))
			if finalized {
				repo.completeErr = errors.New("DB update interrupted")
				require.Error(t, h.OnBatchFinalized(t.Context(), client.BatchFinalizedEvent{Id: e.Id, Txid: h.recoveryAttempt.txid}))
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			h.abandonRecovery(ctx)
			attempts, err := h.delegate.recovery.Attempts(t.Context())
			require.NoError(t, err)
			if finalized {
				require.Equal(t, recovery.AttemptFinalized, attempts[0].Phase)
				require.Empty(t, attempts[0].QuarantineReason)
				require.Zero(t, repo.failed)
			} else {
				require.Equal(t, recovery.AttemptSubmissionUnknown, attempts[0].Phase)
				require.NotEmpty(t, attempts[0].QuarantineReason)
				require.Equal(t, 1, repo.failed)
			}
		})
	}
}

func TestProtectedFinalizedEvidenceSurvivesLaterStreamEvents(t *testing.T) {
	for _, later := range []string{"failed", "different-finalization"} {
		t.Run(later, func(t *testing.T) {
			h, repo := gateHandler(t)
			e := gateEvent(t)
			require.NoError(t, h.finalizeRecovery(t.Context(), e, gateReceipt, func() error { return nil }))
			final := client.BatchFinalizedEvent{Id: e.Id, Txid: h.recoveryAttempt.txid}
			repo.completeErr = errors.New("task database unavailable")
			require.Error(t, h.OnBatchFinalized(t.Context(), final))
			before, err := h.delegate.recovery.Attempts(t.Context())
			require.NoError(t, err)
			require.Equal(t, recovery.AttemptFinalized, before[0].Phase)
			if later == "failed" {
				require.Error(t, h.OnBatchFailed(t.Context(), client.BatchFailedEvent{Id: e.Id}))
			} else {
				require.Error(t, h.OnBatchFinalized(t.Context(), client.BatchFinalizedEvent{Id: e.Id, Txid: strings.Repeat("9", 64)}))
			}
			after, err := h.delegate.recovery.Attempts(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Empty(t, after[0].QuarantineReason)
			require.Zero(t, repo.failed)
			repo.completeErr = nil
			require.NoError(t, h.OnBatchFinalized(t.Context(), final))
			require.Equal(t, 2, repo.completed)
		})
	}
}
