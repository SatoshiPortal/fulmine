package application

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ArkLabsHQ/fulmine/internal/core/domain"
	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"github.com/btcsuite/btcd/wire"
)

const protectedQuarantinePrefix = "protected recovery quarantined:"

func protectedAttemptReason(a recovery.ProtectedAttempt) string {
	return fmt.Sprintf("%s phase=%s batch=%s commitment=%s; preserve task DB, attempt and encrypted outboxes; reconcile independently before any retry",
		protectedQuarantinePrefix, a.Phase, a.BatchID, a.CommitmentTxID)
}

// restoreProtectedTask returns handled=true whenever scheduling is unsafe.
// Only an exact final event already recorded before the crash permits replay of
// the task DB completion. No network request or inferred completion occurs here.
func (s *DelegateService) restoreProtectedTask(ctx context.Context, task *domain.DelegateTask, quarantine bool) (bool, error) {
	if task == nil {
		return true, fmt.Errorf("protected task missing")
	}
	if task.RecoveryRegistration == "" {
		return false, nil
	}
	if s.recovery == nil {
		if quarantine {
			if err := s.svc.dbSvc.Delegate().FailTasks(ctx, protectedQuarantinePrefix+" recovery directory unavailable; restore the original publisher directory before reconciliation", task.ID); err != nil {
				return true, err
			}
		}
		return true, fmt.Errorf("protected task requires its retained recovery directory")
	}
	attempts, err := s.recovery.Attempts(ctx)
	if err != nil {
		if quarantine {
			reason := protectedQuarantinePrefix + " retained attempt storage unreadable; preserve task DB and recovery directory; verify storage before retry"
			if failErr := s.svc.dbSvc.Delegate().FailTasks(ctx, reason, task.ID); failErr != nil {
				return true, failErr
			}
		}
		return true, err
	}
	for _, a := range attempts {
		if !slices.Contains(a.TaskIDs, task.ID) {
			continue
		}
		if a.Phase == recovery.AttemptFinalized && a.QuarantineReason == "" {
			return true, s.svc.dbSvc.Delegate().CompleteTasks(ctx, a.CommitmentTxID, task.ID)
		}
		if !quarantine {
			return true, fmt.Errorf("%s", protectedAttemptReason(a))
		}
		if a.QuarantineReason == "" {
			a.QuarantineReason = "restart encountered an unfinished protected attempt"
			if err := s.recovery.SaveAttempt(ctx, a); err != nil {
				return true, err
			}
		}
		reason := protectedAttemptReason(a)
		if err := s.svc.dbSvc.Delegate().FailTasks(ctx, reason, task.ID); err != nil {
			return true, err
		}
		return true, fmt.Errorf("%s", reason)
	}
	r, err := recovery.ParseRegistration(task.RecoveryRegistration)
	if err != nil {
		return true, fmt.Errorf("cannot read protected registration: %w", err)
	}
	grants, err := s.recovery.RetainedOutboxGrants(ctx)
	if err != nil {
		if quarantine {
			if failErr := s.svc.dbSvc.Delegate().FailTasks(ctx, protectedQuarantinePrefix+" retained outbox association unverifiable; preserve task DB and recovery directory; reconcile before retry", task.ID); failErr != nil {
				return true, failErr
			}
		}
		return true, err
	}
	if grants[r.Grant.ID] {
		reason := protectedQuarantinePrefix + " legacy outbox without attempt; preserve task DB and outboxes; submission outcome unknown"
		if !quarantine {
			return true, fmt.Errorf("%s", reason)
		}
		if err := s.svc.dbSvc.Delegate().FailTasks(ctx, reason, task.ID); err != nil {
			return true, err
		}
		return true, fmt.Errorf("%s", reason)
	}
	return false, nil
}

func overlaps(a, b []wire.OutPoint) bool {
	for _, point := range a {
		if slices.Contains(b, point) {
			return true
		}
	}
	return false
}

// Failed/quarantined tasks are deliberately not pending. Consult their retained
// facts as well so allowReplace or a different intent cannot bypass quarantine.
func (s *DelegateService) checkProtectedOverlap(ctx context.Context, inputs []wire.OutPoint) error {
	repo := s.svc.dbSvc.Delegate()
	if s.recovery != nil {
		attempts, err := s.recovery.Attempts(ctx)
		if err != nil {
			return err
		}
		for _, a := range attempts {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, id := range a.TaskIDs {
				if err := ctx.Err(); err != nil {
					return err
				}
				task, err := repo.GetByID(ctx, id)
				if err != nil {
					return fmt.Errorf("retained attempt requires its original task DB: %w", err)
				}
				if task == nil {
					return fmt.Errorf("retained attempt task missing")
				}
				if overlaps(inputs, task.Intent.Inputs) {
					return fmt.Errorf("input belongs to retained protected attempt batch=%s commitment=%s; reconcile before replacing", a.BatchID, a.CommitmentTxID)
				}
			}
		}
	}
	// A disabled/missing manager must not turn retained protected tasks into
	// unprotected delegation. Otherwise only legacy quarantines need a DB scan.
	statuses := []domain.DelegateTaskStatus{domain.DelegateTaskStatusFailed}
	if s.recovery == nil {
		statuses = append(statuses, domain.DelegateTaskStatusPending, domain.DelegateTaskStatusCancelled, domain.DelegateTaskStatusCompleted)
	}
	for _, status := range statuses {
		for offset := 0; ; offset += 100 {
			if err := ctx.Err(); err != nil {
				return err
			}
			if offset >= 10000 {
				return fmt.Errorf("protected task inspection limit reached; reconcile retained task history")
			}
			tasks, err := repo.GetAll(ctx, status, 100, offset)
			if err != nil {
				return err
			}
			for _, task := range tasks {
				if err := ctx.Err(); err != nil {
					return err
				}
				if (strings.HasPrefix(task.FailReason, protectedQuarantinePrefix) || (s.recovery == nil && task.RecoveryRegistration != "")) && overlaps(inputs, task.Intent.Inputs) {
					return fmt.Errorf("input belongs to a quarantined protected task; reconcile before replacing")
				}
			}
			if len(tasks) < 100 {
				break
			}
		}
	}
	return nil
}

// Do not let generic spent notifications turn an uncertain protected attempt
// into a cancellation: offchain consumption alone does not identify its outcome.
func (s *DelegateService) cancellableUnprotectedTasks(ctx context.Context, ids []string) ([]string, error) {
	protected := make(map[string]bool)
	grants := make(map[string]bool)
	if s.recovery != nil {
		attempts, err := s.recovery.Attempts(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range attempts {
			for _, id := range a.TaskIDs {
				protected[id] = true
			}
		}
		grants, err = s.recovery.RetainedOutboxGrants(ctx)
		if err != nil {
			return nil, err
		}
	}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if protected[id] {
			continue
		}
		task, err := s.svc.dbSvc.Delegate().GetByID(ctx, id)
		if err != nil {
			return nil, err
		}
		if task == nil {
			return nil, fmt.Errorf("spent-notification task missing")
		}
		if task.RecoveryRegistration != "" {
			if s.recovery == nil {
				continue
			}
			r, err := recovery.ParseRegistration(task.RecoveryRegistration)
			if err != nil {
				return nil, err
			}
			if grants[r.Grant.ID] {
				continue
			}
		}
		result = append(result, id)
	}
	return result, nil
}
