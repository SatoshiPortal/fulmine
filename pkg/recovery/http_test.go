package recovery

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackupResponseBoundaries(t *testing.T) {
	for _, mode := range []string{"empty", "truncated", "trailing_json", "oversize", "compressed_oversize", "non_success"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "empty":
					return
				case "truncated":
					_, _ = w.Write([]byte(`{"records":`))
				case "trailing_json":
					_, _ = w.Write([]byte(`{} {}`))
				case "oversize":
					_, _ = w.Write([]byte(strings.Repeat(" ", 2*1024*1024+1)))
				case "compressed_oversize":
					w.Header().Set("Content-Encoding", "gzip")
					compressed := gzip.NewWriter(w)
					_, _ = compressed.Write([]byte(strings.Repeat(" ", 2*1024*1024+1)))
					_ = compressed.Close()
				case "non_success":
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`{"records":[],"snapshot":0}`))
				}
			}))
			defer server.Close()
			_, err := FetchPage(t.Context(), server.URL, testKey(t), 0, 0)
			require.Error(t, err)
			if strings.Contains(mode, "oversize") {
				require.ErrorContains(t, err, "response too large")
			}
		})
	}
}

func TestFetchOriginPolicy(t *testing.T) {
	for _, origin := range []string{"http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid/path", "https://example.invalid?query", "https://example.invalid#fragment", "file:///tmp/backup", ""} {
		t.Run(origin, func(t *testing.T) {
			// A nil key proves validation runs before signing or issuing a request.
			_, err := FetchPage(t.Context(), origin, nil, 0, 0)
			require.ErrorContains(t, err, "recovery origin must be")
		})
	}
	for _, origin := range []string{"https://backup.example", "http://127.0.0.1:9081"} {
		require.NoError(t, validateOrigin(origin))
	}
}

func TestBackupRedirectDoesNotForwardAuthorization(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		_, _ = w.Write([]byte(`{"records":[],"snapshot":0}`))
	}))
	defer target.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			_, err := FetchPage(t.Context(), server.URL, testKey(t), 0, 0)
			require.ErrorContains(t, err, "redirects disabled")
		})
	}
	require.Zero(t, targetCalls.Load())
}

func TestBackupStalledResponseHonorsCancellation(t *testing.T) {
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		_, _ = w.Write([]byte(`{"records":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := FetchPage(ctx, server.URL, testKey(t), 0, 0)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out request left the server connection open")
	}
}
