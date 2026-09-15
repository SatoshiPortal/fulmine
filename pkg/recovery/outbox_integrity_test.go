package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetryAuthenticatesSavedEnvelope(t *testing.T) {
	for _, mode := range []string{"ciphertext", "grant_signature", "publisher_attestation", "event_signature", "byte_count", "oversized_outbox"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request StoreRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				// A matching receipt alone must not bless corrupt local recovery data.
				require.NoError(t, json.NewEncoder(w).Encode(Receipt{ID: 1, Hash: request.Hash}))
			}))
			defer server.Close()
			dir := t.TempDir()
			manager, err := NewManager(dir, server.URL)
			require.NoError(t, err)
			registration := Registration{Grant: testGrant(t, testKey(t), manager.Public(), server.URL)}
			require.NoError(t, manager.Deliver(t.Context(), "intent", "batch", registration, []byte("candidate")))
			require.NoError(t, manager.Close())
			path := filepath.Join(dir, fmt.Sprintf("outbox-%x.json", Digest("intent", "batch")))
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			var box outbox
			require.NoError(t, json.Unmarshal(raw, &box))
			switch mode {
			case "ciphertext":
				box.Request.Ciphertext = base64.StdEncoding.EncodeToString([]byte("broken"))
				box.Request.Hash = Hash([]byte("broken"))
				box.Request.Bytes = 6
			case "grant_signature":
				box.Request.Grant.Signature = strings.Repeat("0", 128)
			case "byte_count":
				box.Request.Bytes++
			case "publisher_attestation", "event_signature":
				raw, err := base64.StdEncoding.DecodeString(box.Request.Ciphertext)
				require.NoError(t, err)
				var envelope Envelope
				require.NoError(t, json.Unmarshal(raw, &envelope))
				if mode == "publisher_attestation" {
					envelope.PublisherSignature = strings.Repeat("0", 128)
				} else {
					envelope.Event.Sig = strings.Repeat("0", 128)
				}
				raw, err = json.Marshal(envelope)
				require.NoError(t, err)
				box.Request.Ciphertext = base64.StdEncoding.EncodeToString(raw)
				box.Request.Hash = Hash(raw)
				box.Request.Bytes = uint64(len(raw))
			}
			require.NoError(t, saveBox(path, box))
			if mode == "oversized_outbox" {
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				require.NoError(t, err)
				_, err = f.WriteString(strings.Repeat(" ", 256*1024))
				require.NoError(t, err)
				require.NoError(t, f.Close())
			}
			manager, err = NewManager(dir, server.URL)
			require.NoError(t, err)
			defer manager.Close()
			err = manager.Deliver(t.Context(), "intent", "batch", registration, []byte("candidate"))
			require.Error(t, err)
			require.Equal(t, 1, calls, "corrupt outbox must fail before an HTTP request")
		})
	}
}
