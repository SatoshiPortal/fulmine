package recovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bip39 "github.com/tyler-smith/go-bip39"
)

// Exercise acknowledged SQLite records across abrupt server death, including a
// publisher restart with an unacknowledged outbox and recovery without its keys.
// All processes and data belong to this test; no running deployment is changed.
func TestBackupCrashAndSeedRecovery(t *testing.T) {
	binary := os.Getenv("BACKUP_PROTOTYPE_BIN")
	if binary == "" {
		t.Skip("requires Rust backup binary")
	}
	entropy, err := bip39.NewEntropy(256)
	require.NoError(t, err)
	mnemonic, err := bip39.NewMnemonic(entropy)
	require.NoError(t, err)
	clear(entropy)
	owner := liveNostrKey(t, mnemonic)
	defer owner.Zero()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	origin := "http://" + address
	publisherDir := filepath.Join(t.TempDir(), "publisher")
	manager, err := NewManager(publisherDir, origin)
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })
	publisher := manager.Public()
	grant := testGrant(t, owner, publisher, origin)
	grant.MaxRecords = 12
	grant.Signature, err = Sign(owner, grant.Digest())
	require.NoError(t, err)
	registration := Registration{Grant: grant}
	database := filepath.Join(t.TempDir(), "backup.sqlite")
	var server *exec.Cmd
	stop := func() {
		if server != nil {
			require.NoError(t, server.Process.Kill())
			require.Error(t, server.Wait())
			server = nil
		}
	}
	t.Cleanup(stop)
	start := func() {
		server = exec.Command(binary, database, address, origin, publisher)
		require.NoError(t, server.Start())
		require.Eventually(t, func() bool {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			_, err := FetchPage(ctx, origin, owner, 0, 0)
			return err == nil
		}, 5*time.Second, 20*time.Millisecond)
	}
	start()
	want := make(map[string]string)
	for epoch := range 4 {
		for offset := range 3 {
			id := fmt.Sprintf("candidate-%d", epoch*3+offset)
			plain := []byte("signed branch fixture " + id)
			if offset == 0 {
				stop()
				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				_, err := manager.DeliverReceipt(ctx, id, id, registration, plain)
				cancel()
				require.Error(t, err, "offline backup must not produce a receipt")
				require.NoError(t, manager.Close())
				manager, err = NewManager(publisherDir, origin)
				require.NoError(t, err)
				require.Equal(t, publisher, manager.Public())
				start()
			}
			receipt, err := manager.DeliverReceipt(t.Context(), id, id, registration, plain)
			require.NoError(t, err)
			want[receipt.Hash] = string(plain)
		}
		stop() // SIGKILL immediately after the last durable receipt.
		start()
	}
	require.Len(t, want, 12)
	require.NoError(t, manager.Close())
	require.NoError(t, os.RemoveAll(publisherDir))
	owner.Zero()
	recovered := liveNostrKey(t, mnemonic)
	defer recovered.Zero()
	destination := t.TempDir()
	count, err := FetchToDirectory(t.Context(), origin, recovered, destination)
	require.NoError(t, err)
	require.Equal(t, 12, count, "both fetch pages must survive every server crash")
	for hash, plain := range want {
		raw, err := os.ReadFile(filepath.Join(destination, hash+".json"))
		require.NoError(t, err)
		require.Equal(t, plain, string(raw))
	}
	other, err := FetchPage(t.Context(), origin, testKey(t), 0, 0)
	require.NoError(t, err)
	require.Empty(t, other.Records, "another authenticated owner cannot list these records")
	t.Log("12 acknowledged records survived 8 backup SIGKILLs and 4 publisher restarts; seed-derived key fetched both pages after publisher data deletion")
}
