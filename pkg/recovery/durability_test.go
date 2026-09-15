package recovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPublisherOwnershipAndKeyValidation(t *testing.T) {
	dir := t.TempDir()
	origin := "http://127.0.0.1:9000"
	m, err := NewManager(dir, origin)
	require.NoError(t, err)
	pub := m.Public()
	_, err = NewManager(dir, origin)
	require.Error(t, err)
	require.NoError(t, m.Close())
	m, err = NewManager(dir, origin)
	require.NoError(t, err)
	require.Equal(t, pub, m.Public())
	require.NoError(t, m.Close())
	for _, key := range [][]byte{make([]byte, 32), []byte("short"), append([]byte{}, []byte(strings.Repeat("\xff", 32))...)} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "publisher.key"), key, 0600))
		_, err = NewManager(dir, origin)
		require.Error(t, err)
	}
}
func TestDeliveryLockHonorsCancellation(t *testing.T) {
	m, err := NewManager(t.TempDir(), "http://127.0.0.1:9000")
	require.NoError(t, err)
	defer m.Close()
	require.NoError(t, m.acquire(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = m.DeliverReceipt(ctx, "intent", "batch", Registration{}, []byte("branch"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	m.release()
}

// Invoked only by TestCommittedUploadLostResponse. The uncertain first process
// stays alive so the parent can kill it, exercising OS lock release on crash.
func TestDeliverySubprocess(t *testing.T) {
	dir := os.Getenv("RECOVERY_TEST_PROCESS_DIR")
	if dir == "" {
		return
	}
	m, err := NewManager(dir, os.Getenv("RECOVERY_TEST_PROCESS_ORIGIN"))
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(dir, "process-registration.json"))
	require.NoError(t, err)
	registration, err := ParseRegistration(string(raw))
	require.NoError(t, err)
	err = m.Deliver(context.Background(), "intent", "batch", registration, []byte("process-branch"))
	if os.Getenv("RECOVERY_TEST_UNCERTAIN") == "1" {
		require.Error(t, err)
		fmt.Println("uncertain")
		select {}
	}
	require.NoError(t, err)
	require.NoError(t, m.Close())
}

func TestCommittedUploadLostResponse(t *testing.T) {
	binary := os.Getenv("BACKUP_PROTOTYPE_BIN")
	if binary == "" {
		t.Skip("requires Rust backup binary")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	backendAddr := l.Addr().String()
	require.NoError(t, l.Close())
	target, err := url.Parse("http://" + backendAddr)
	require.NoError(t, err)
	var dropped atomic.Bool
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(r *http.Response) error {
		if r.Request.URL.Path == "/api/v1/arkade-recovery-records" && r.StatusCode == 200 && dropped.CompareAndSwap(false, true) {
			r.Body.Close()
			return errors.New("drop after durable commit")
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		conn, _, e := w.(http.Hijacker).Hijack()
		if e == nil {
			conn.Close()
		}
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	dir := t.TempDir()
	m, err := NewManager(dir, server.URL)
	require.NoError(t, err)
	owner := testKey(t)
	grant := testGrant(t, owner, m.Public(), server.URL)
	grant.MaxRecords = 1
	grant.Signature, err = Sign(owner, grant.Digest())
	require.NoError(t, err)
	raw, err := json.Marshal(Registration{Grant: grant})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "process-registration.json"), raw, 0600))
	cmd := exec.Command(binary, filepath.Join(t.TempDir(), "backup.sqlite"), backendAddr, server.URL, m.Public())
	require.NoError(t, cmd.Start())
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	require.Eventually(t, func() bool {
		c, e := net.DialTimeout("tcp", backendAddr, 20*time.Millisecond)
		if e != nil {
			return false
		}
		c.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)
	require.NoError(t, m.Close())
	child := func(uncertain string) *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=^TestDeliverySubprocess$", "-test.timeout=20s")
		c.Env = append(os.Environ(), "RECOVERY_TEST_PROCESS_DIR="+dir, "RECOVERY_TEST_PROCESS_ORIGIN="+server.URL, "RECOVERY_TEST_UNCERTAIN="+uncertain)
		return c
	}
	first := child("1")
	output, err := first.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, first.Start())
	defer func() {
		if first.Process != nil {
			first.Process.Kill()
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			if scanner.Text() == "uncertain" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		require.True(t, ok)
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not observe lost response")
	}
	before, err := os.ReadFile(filepath.Join(dir, "outbox-"+fmt.Sprintf("%x", Digest("intent", "batch"))+".json"))
	require.NoError(t, err)
	require.NoError(t, first.Process.Kill())
	require.Error(t, first.Wait())
	second := child("0")
	log, err := second.CombinedOutput()
	require.NoError(t, err, string(log))
	page, err := FetchPage(context.Background(), server.URL, owner, 0, 0)
	require.NoError(t, err)
	require.Len(t, page.Records, 1)
	var box outbox
	require.NoError(t, json.Unmarshal(before, &box))
	require.Equal(t, box.Request.Ciphertext, page.Records[0].Ciphertext)
	plain, err := Open(page.Records[0], owner)
	require.NoError(t, err)
	require.Equal(t, "process-branch", string(plain))
	require.True(t, dropped.Load())
}

func TestReceiptAndLocalWriteFailures(t *testing.T) {
	for _, failure := range []string{"wrong receipt", "before save", "after receipt"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "outbox-"+fmt.Sprintf("%x", Digest("intent", "batch"))+".json")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var req StoreRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				hash := req.Hash
				if failure == "wrong receipt" {
					hash = strings.Repeat("0", 64)
				}
				if failure == "after receipt" {
					require.NoError(t, os.Rename(path, path+".retained"))
					require.NoError(t, os.Mkdir(path, 0700))
				}
				json.NewEncoder(w).Encode(Receipt{ID: 1, Hash: hash})
			}))
			defer server.Close()
			m, err := NewManager(dir, server.URL)
			require.NoError(t, err)
			defer m.Close()
			registration := Registration{Grant: testGrant(t, testKey(t), m.Public(), server.URL)}
			if failure == "before save" {
				require.NoError(t, os.Mkdir(path, 0700))
			}
			require.Error(t, m.Deliver(context.Background(), "intent", "batch", registration, []byte("branch")))
			if failure == "before save" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}
