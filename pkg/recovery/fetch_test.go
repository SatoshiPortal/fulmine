package recovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchResumeAndLocalIntegrity(t *testing.T) {
	owner, publisher := testKey(t), testKey(t)
	var records []Record
	fail := true
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var req FetchRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.NoError(t, Verify(Public(owner), req.Digest(), req.Signature))
		if req.After == 1 && fail {
			w.WriteHeader(503)
			return
		}
		if req.After == 0 {
			next := uint64(1)
			json.NewEncoder(w).Encode(Page{Records: records[:1], Snapshot: 2, NextAfter: &next})
		} else {
			json.NewEncoder(w).Encode(Page{Records: records[1:], Snapshot: 2})
		}
	}))
	defer server.Close()
	grant := testGrant(t, owner, Public(publisher), server.URL)
	for i := int64(1); i <= 2; i++ {
		sealed, err := Seal(grant, publisher, []byte(strings.Repeat("x", int(i))))
		require.NoError(t, err)
		records = append(records, Record{ID: i, Grant: grant, Hash: sealed.Hash, Ciphertext: sealed.Ciphertext})
	}
	dir := filepath.Join(t.TempDir(), "fetch")
	count, err := FetchToDirectory(context.Background(), server.URL, owner, dir)
	require.Error(t, err)
	require.Equal(t, 1, count)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	require.NoError(t, err)
	var manifest fetchManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.False(t, manifest.Complete)
	fail = false
	count, err = FetchToDirectory(context.Background(), server.URL, owner, dir)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	before := requests
	_, err = FetchToDirectory(context.Background(), server.URL, testKey(t), dir)
	require.Error(t, err)
	require.Equal(t, before, requests)
	require.NoError(t, os.WriteFile(filepath.Join(dir, records[0].Hash+".json"), []byte("changed"), 0600))
	_, err = FetchToDirectory(context.Background(), server.URL, owner, dir)
	require.ErrorContains(t, err, "modified")
	require.Equal(t, before, requests)
}
func TestFetchRejectsMalformedPages(t *testing.T) {
	for _, mode := range []string{"duplicate", "zero_id", "past_snapshot", "non_progress", "cursor_not_last", "wrong_origin", "tampered_record", "snapshot_rollback", "truncated_last_page", "empty_last_page"} {
		t.Run(mode, func(t *testing.T) {
			owner, publisher := testKey(t), testKey(t)
			var page Page
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; json.NewEncoder(w).Encode(page) }))
			defer server.Close()
			grant := testGrant(t, owner, Public(publisher), server.URL)
			sealed, err := Seal(grant, publisher, []byte("candidate"))
			require.NoError(t, err)
			record := Record{ID: 1, Grant: grant, Hash: sealed.Hash, Ciphertext: sealed.Ciphertext}
			page = Page{Records: []Record{record}, Snapshot: 2}
			next := uint64(0)
			switch mode {
			case "duplicate":
				page.Records = append(page.Records, record)
			case "zero_id":
				page.Records[0].ID = 0
			case "past_snapshot":
				page.Records[0].ID = 3
			case "non_progress":
				page.NextAfter = &next
			case "cursor_not_last":
				next = 2
				page.NextAfter = &next
			case "wrong_origin":
				page.Records[0].Grant.Origin = "https://different.example"
			case "tampered_record":
				page.Records[0].Hash = strings.Repeat("0", 64)
			case "snapshot_rollback":
				page.Snapshot = 0
			case "empty_last_page":
				page.Records = []Record{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = FetchToDirectory(ctx, server.URL, owner, t.TempDir())
			require.Error(t, err)
			require.Equal(t, 1, calls)
		})
	}
}

func TestFetchRequiresCompletePageSchema(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"records":[],"snapshot":0}`, `{"records":[],"next_after":null}`, `{"snapshot":0,"next_after":null}`, `{"records":null,"snapshot":0,"next_after":null}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			dir := t.TempDir()
			_, err := FetchToDirectory(t.Context(), server.URL, testKey(t), dir)
			require.Error(t, err)
			raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			require.NoError(t, err)
			var manifest fetchManifest
			require.NoError(t, json.Unmarshal(raw, &manifest))
			require.False(t, manifest.Complete)
		})
	}
}
