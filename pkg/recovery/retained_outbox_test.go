package recovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetainedOutboxAssociationAuthenticatesBeforeScheduling(t *testing.T) {
	for _, mode := range []string{"grant_id", "grant_signature", "byte_count", "publisher", "origin", "ciphertext", "unrelated_box", "filename", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			m, err := NewManager(dir, "https://backup.example")
			require.NoError(t, err)
			defer m.Close()
			m.client.Transport = bindingTransport(func(r *http.Request) (*http.Response, error) {
				var request StoreRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				raw, _ := json.Marshal(Receipt{ID: 1, Hash: request.Hash})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})
			registration := Registration{Grant: testGrant(t, testKey(t), m.Public(), m.Origin())}
			require.NoError(t, m.Deliver(t.Context(), "intent", "batch", registration, []byte("candidate")))
			grants, err := m.RetainedOutboxGrants(t.Context())
			require.NoError(t, err)
			require.True(t, grants[registration.Grant.ID])
			path := filepath.Join(dir, fmt.Sprintf("outbox-%x.json", Digest("intent", "batch")))
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			var box outbox
			require.NoError(t, json.Unmarshal(raw, &box))
			switch mode {
			case "grant_id":
				box.Request.Grant.ID = strings.Repeat("9", 64)
			case "grant_signature":
				box.Request.Grant.Signature = strings.Repeat("0", 128)
			case "byte_count":
				box.Request.Bytes++
			case "publisher":
				box.Request.Grant.Publisher = Public(testKey(t))
			case "origin":
				box.Request.Grant.Origin = "https://unrelated.example"
			case "ciphertext":
				box.Request.Ciphertext = "broken"
			case "unrelated_box":
				other := Registration{Grant: testGrant(t, testKey(t), m.Public(), m.Origin())}
				require.NoError(t, m.Deliver(t.Context(), "unrelated-intent", "other-batch", other, []byte("other")))
				otherPath := filepath.Join(dir, fmt.Sprintf("outbox-%x.json", Digest("unrelated-intent", "other-batch")))
				raw, err = os.ReadFile(otherPath)
				require.NoError(t, err)
				require.NoError(t, json.Unmarshal(raw, &box))
			case "filename":
				path = filepath.Join(dir, "outbox-wrong-name.json")
			case "legacy":
				box.IntentID, box.BatchID = "", ""
			}
			// Re-signing local bindings for inner-auth tests demonstrates those
			// checks cannot be replaced by the publisher's local signature alone.
			if mode == "grant_signature" || mode == "byte_count" || mode == "ciphertext" || mode == "publisher" || mode == "origin" {
				box.BindingSignature, err = Sign(m.key, box.bindingDigest("intent", "batch"))
				require.NoError(t, err)
			}
			require.NoError(t, saveBox(path, box))
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			grants, err = m.RetainedOutboxGrants(t.Context())
			require.Error(t, err)
			require.Nil(t, grants, "unverifiable association must not look like an absent grant")
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
			if mode == "legacy" {
				require.NoError(t, m.Deliver(t.Context(), "intent", "batch", registration, []byte("candidate")))
				grants, err = m.RetainedOutboxGrants(t.Context())
				require.NoError(t, err)
				require.True(t, grants[registration.Grant.ID])
			}
		})
	}
}
