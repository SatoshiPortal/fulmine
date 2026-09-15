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

type bindingTransport func(*http.Request) (*http.Response, error)

func (f bindingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOutboxBindingRejectsValidEnvelopeSubstitution(t *testing.T) {
	for _, mode := range []string{"request_swap", "whole_box_same_plaintext", "whole_box_different_intent", "plaintext_hash", "signature", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			manager, err := NewManager(dir, "https://backup.example")
			require.NoError(t, err)
			defer func() { _ = manager.Close() }()
			calls := 0
			transport := bindingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var req StoreRequest
				require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
				raw, err := json.Marshal(Receipt{ID: 1, Hash: req.Hash})
				require.NoError(t, err)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			})
			manager.client.Transport = transport
			registration := Registration{Grant: testGrant(t, testKey(t), manager.Public(), manager.Origin())}
			plainA, plainB := []byte("candidate A"), []byte("candidate B")
			intentB, batchB := "intent", "batch-b"
			if mode == "whole_box_same_plaintext" || mode == "whole_box_different_intent" {
				plainB = plainA
			}
			if mode == "whole_box_different_intent" {
				intentB, batchB = "different-intent", "batch-a"
			}
			require.NoError(t, manager.Deliver(t.Context(), "intent", "batch-a", registration, plainA))
			require.NoError(t, manager.Deliver(t.Context(), intentB, batchB, registration, plainB))
			require.NoError(t, manager.Close())
			path := func(intent, batch string) string {
				return filepath.Join(dir, fmt.Sprintf("outbox-%x.json", Digest(intent, batch)))
			}
			read := func(intent, batch string) outbox {
				raw, err := os.ReadFile(path(intent, batch))
				require.NoError(t, err)
				var box outbox
				require.NoError(t, json.Unmarshal(raw, &box))
				return box
			}
			a, b := read("intent", "batch-a"), read(intentB, batchB)
			switch mode {
			case "request_swap":
				a.Request = b.Request
			case "whole_box_same_plaintext", "whole_box_different_intent":
				a = b
			case "plaintext_hash":
				a.PlaintextHash = Hash(plainB)
				plainA = plainB
			case "signature":
				a.BindingSignature = strings.Repeat("0", 128)
			case "legacy":
				a.BindingSignature = ""
			}
			target := path("intent", "batch-a")
			require.NoError(t, saveBox(target, a))
			if mode == "legacy" {
				raw, err := os.ReadFile(target)
				require.NoError(t, err)
				var legacy map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &legacy))
				delete(legacy, "binding_signature")
				raw, err = json.Marshal(legacy)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(target, raw, 0600))
			}
			before, err := os.ReadFile(target)
			require.NoError(t, err)
			manager, err = NewManager(dir, "https://backup.example")
			require.NoError(t, err)
			manager.client.Transport = transport
			err = manager.Deliver(t.Context(), "intent", "batch-a", registration, plainA)
			require.Error(t, err, "another candidate's valid envelope must not authorize this candidate")
			if mode == "legacy" {
				require.ErrorContains(t, err, "legacy outbox")
				require.ErrorContains(t, err, "reconciliation")
			}
			require.Equal(t, 2, calls, "invalid binding must fail before another upload")
			after, err := os.ReadFile(target)
			require.NoError(t, err)
			require.Equal(t, before, after, "rejected outbox must remain available for reconciliation")
		})
	}
}
