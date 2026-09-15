package recovery

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHardeningReviewHistoricalRetryAndEmptyOwner(t *testing.T) {
	binary := os.Getenv("BACKUP_PROTOTYPE_BIN")
	if binary == "" {
		t.Skip("requires Rust backup binary")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	origin := "http://" + address
	dir := t.TempDir()
	manager, err := NewManager(dir, origin)
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })
	owner := testKey(t)
	server := exec.Command(binary, filepath.Join(t.TempDir(), "backup.sqlite"), address, origin, manager.Public())
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_, err := FetchPage(ctx, origin, owner, 0, 0)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	grant := testGrant(t, owner, manager.Public(), origin)
	grant.ExpiresAt = uint64(time.Now().Unix()) + 1
	grant.MaxRecords = 1
	grant.Signature, err = Sign(owner, grant.Digest())
	require.NoError(t, err)
	registration := Registration{Grant: grant}
	first, err := manager.DeliverReceipt(t.Context(), "intent", "batch", registration, []byte("historical candidate"))
	require.NoError(t, err)
	require.NoError(t, manager.Close())
	require.Eventually(t, func() bool { return uint64(time.Now().Unix()) > grant.ExpiresAt }, 3*time.Second, 20*time.Millisecond)
	manager, err = NewManager(dir, origin)
	require.NoError(t, err)
	retried, err := manager.DeliverReceipt(t.Context(), "intent", "batch", registration, []byte("historical candidate"))
	require.NoError(t, err)
	require.Equal(t, first, retried, "an expired append window must not reject an already committed exact retry")
	_, err = manager.DeliverReceipt(t.Context(), "intent", "new-batch", registration, []byte("new candidate"))
	require.Error(t, err, "an expired grant must still refuse a new record")
	page, err := FetchPage(t.Context(), origin, owner, 0, 0)
	require.NoError(t, err)
	require.Len(t, page.Records, 1)
	plain, err := Open(page.Records[0], owner)
	require.NoError(t, err)
	require.Equal(t, "historical candidate", string(plain))

	// The database is nonempty, but the second owner has a legitimate empty snapshot.
	emptyDir := t.TempDir()
	count, err := FetchToDirectory(t.Context(), origin, testKey(t), emptyDir)
	require.NoError(t, err)
	require.Zero(t, count)
	raw, err := os.ReadFile(filepath.Join(emptyDir, "manifest.json"))
	require.NoError(t, err)
	var manifest fetchManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.True(t, manifest.Complete)
	require.Zero(t, manifest.Snapshot)
	require.Empty(t, manifest.Files)
}

func TestHardeningReviewIncompleteFinalPageResumes(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		name := "empty"
		if truncated {
			name = "truncated"
		}
		t.Run(name, func(t *testing.T) {
			owner, publisher := testKey(t), testKey(t)
			var records []Record
			var requests []FetchRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request FetchRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.NoError(t, Verify(Public(owner), request.Digest(), request.Signature))
				requests = append(requests, request)
				page := Page{Records: records[1:], Snapshot: 7}
				if len(requests) == 1 {
					next := uint64(2)
					page.Records = records[:1]
					page.NextAfter = &next
				} else if len(requests) == 2 {
					page.Records = []Record{}
					if truncated {
						page.Records = records[1:2]
					}
				}
				require.NoError(t, json.NewEncoder(w).Encode(page))
			}))
			defer server.Close()
			grant := testGrant(t, owner, Public(publisher), server.URL)
			// Gaps are valid: other owners can occupy IDs between these records.
			for _, id := range []int64{2, 5, 7} {
				sealed, err := Seal(grant, publisher, []byte{byte(id)})
				require.NoError(t, err)
				records = append(records, Record{ID: id, Grant: grant, Hash: sealed.Hash, Ciphertext: sealed.Ciphertext})
			}
			dir := t.TempDir()
			_, err := FetchToDirectory(t.Context(), server.URL, owner, dir)
			require.ErrorContains(t, err, "incomplete final recovery page")
			raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			require.NoError(t, err)
			var manifest fetchManifest
			require.NoError(t, json.Unmarshal(raw, &manifest))
			require.False(t, manifest.Complete)
			require.Equal(t, uint64(2), manifest.After)
			require.Equal(t, uint64(7), manifest.Snapshot)
			count, err := FetchToDirectory(t.Context(), server.URL, owner, dir)
			require.NoError(t, err)
			require.Equal(t, 3, count)
			require.Len(t, requests, 3)
			require.Equal(t, uint64(2), requests[2].After)
			require.Equal(t, uint64(7), requests[2].Snapshot)
			for _, record := range records {
				raw, err := os.ReadFile(filepath.Join(dir, record.Hash+".json"))
				require.NoError(t, err)
				require.Equal(t, []byte{byte(record.ID)}, raw)
			}
		})
	}
}
