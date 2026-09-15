package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// BenchmarkProtectedAttemptHistory measures warm-cache scans and durable phase
// writes at representative small-history counts and near the retention byte cap.
// The large case uses valid PSBT unknown metadata to exercise the parser at its
// supported size; it is a bound case, not an estimate of typical Ark candidates.
// Fixture files are written directly so setup does not benchmark O(n²) admission.
func BenchmarkProtectedAttemptHistory(b *testing.B) {
	for _, fixture := range []struct {
		name          string
		count         int
		metadataBytes int
	}{
		{"100_small", 100, 0},
		{"1000_small", 1000, 0},
		{"1000_near_byte_cap", 1000, 24*1024 - 512},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			manager, first, total := benchmarkAttemptHistory(b, fixture.count, fixture.metadataBytes)
			defer manager.Close()
			for _, operation := range []string{"Attempts", "SaveAttempt"} {
				b.Run(operation, func(b *testing.B) {
					b.ReportAllocs()
					var maximum time.Duration
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						start := time.Now()
						if operation == "Attempts" {
							attempts, err := manager.Attempts(context.Background())
							if err != nil || len(attempts) != fixture.count {
								b.Fatalf("scan: count=%d error=%v", len(attempts), err)
							}
						} else if err := manager.SaveAttempt(context.Background(), first); err != nil {
							b.Fatal(err)
						}
						if elapsed := time.Since(start); elapsed > maximum {
							maximum = elapsed
						}
					}
					b.StopTimer()
					b.ReportMetric(maximum.Seconds()*1000, "max_ms")
					b.ReportMetric(float64(total)/(1024*1024), "history_MiB")
					b.ReportMetric(float64(fixture.count), "journals")
				})
			}
		})
	}
}

func benchmarkAttemptHistory(b *testing.B, count, metadataBytes int) (*Manager, ProtectedAttempt, int64) {
	b.Helper()
	manager, err := NewManager(b.TempDir(), "http://127.0.0.1:9081")
	if err != nil {
		b.Fatal(err)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(wire.NewTxOut(100, []byte{0x51}))
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		b.Fatal(err)
	}
	if metadataBytes != 0 {
		packet.Unknowns = []*psbt.Unknown{{Key: []byte{0xfc, 0x01, 'b'}, Value: make([]byte, metadataBytes)}}
	}
	encoded, err := packet.B64Encode()
	if err != nil {
		b.Fatal(err)
	}
	var first ProtectedAttempt
	var total int64
	for index := 0; index < count; index++ {
		attempt := ProtectedAttempt{
			Version: 1, BatchID: fmt.Sprintf("batch-%04d", index), CommitmentTxID: tx.TxID(),
			CandidatePSBT: encoded, TaskIDs: []string{fmt.Sprintf("task-%04d", index)}, Phase: AttemptPreparing,
		}
		if err := attempt.validate(); err != nil {
			b.Fatal(err)
		}
		signature, err := Sign(manager.key, attempt.digest())
		if err != nil {
			b.Fatal(err)
		}
		raw, err := json.Marshal(signedAttempt{Attempt: attempt, Signature: signature})
		if err != nil {
			b.Fatal(err)
		}
		total += int64(len(raw))
		if total > maxAttemptStorageBytes {
			b.Fatal("benchmark fixture exceeds supported byte cap")
		}
		if err := os.WriteFile(manager.attemptPath(attempt.BatchID), raw, 0600); err != nil {
			b.Fatal(err)
		}
		if index == 0 {
			first = attempt
		}
	}
	return manager, first, total
}
