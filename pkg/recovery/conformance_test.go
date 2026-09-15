package recovery

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ArkLabsHQ/fulmine/test/recovery/fixtures"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestRecoveryWireConformance(t *testing.T) {
	require.Equal(t, fixtures.WireV1SHA256, Hash(fixtures.WireV1), "golden fixture bytes changed")
	var f struct {
		Domain        string            `json:"domain"`
		Grant         Grant             `json:"grant"`
		Store         StoreRequest      `json:"store"`
		Fetch         FetchRequest      `json:"fetch"`
		Record        Record            `json:"record"`
		Envelope      Envelope          `json:"envelope"`
		BundleJSON    string            `json:"bundle_json"`
		Digests       map[string]string `json:"digests"`
		Keys          map[string]string `json:"public_test_keys"`
		ScopeEncoding struct {
			Message     string   `json:"message"`
			Proof       string   `json:"proof"`
			Outputs     []Output `json:"outputs"`
			OutputsJSON string   `json:"outputs_json"`
			Digest      string   `json:"digest"`
		} `json:"scope_encoding"`
	}
	require.NoError(t, json.Unmarshal(fixtures.WireV1, &f))
	require.Equal(t, Domain, f.Domain)
	var sections map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(fixtures.WireV1, &sections))
	for name, value := range map[string]any{"grant": f.Grant, "store": f.Store, "fetch": f.Fetch, "record": f.Record, "envelope": f.Envelope} {
		require.JSONEq(t, string(sections[name]), string(mustMarshal(t, value)), name+" schema changed")
	}
	require.Equal(t, f.ScopeEncoding.OutputsJSON, string(mustMarshal(t, f.ScopeEncoding.Outputs)))
	require.Equal(t, f.ScopeEncoding.Digest, Scope(f.ScopeEncoding.Message, f.ScopeEncoding.Proof, f.ScopeEncoding.Outputs))

	for name, digest := range map[string][]byte{"grant": f.Grant.Digest(), "store": f.Store.Digest(), "fetch": f.Fetch.Digest()} {
		require.Equal(t, f.Digests[name], hex.EncodeToString(digest), name)
	}
	require.NoError(t, Verify(f.Grant.Owner, f.Grant.Digest(), f.Grant.Signature))
	require.NoError(t, Verify(f.Grant.Publisher, f.Store.Digest(), f.Store.Signature))
	require.NoError(t, Verify(f.Fetch.Owner, f.Fetch.Digest(), f.Fetch.Signature))
	require.Equal(t, f.Grant, f.Store.Grant)
	require.Equal(t, f.Grant, f.Record.Grant)
	require.Equal(t, f.Digests["ciphertext"], f.Store.Hash)
	raw, err := base64.StdEncoding.DecodeString(f.Store.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, uint64(len(raw)), f.Store.Bytes)
	require.Equal(t, f.Store.Hash, Hash(raw))
	require.JSONEq(t, string(raw), string(mustMarshal(t, f.Envelope)))
	eventDigest, err := f.Envelope.Event.digest()
	require.NoError(t, err)
	require.Equal(t, f.Digests["event"], hex.EncodeToString(eventDigest))
	require.Equal(t, f.Digests["attestation"], hex.EncodeToString(attestation(f.Grant, f.Envelope.Event.ID)))
	keyBytes, err := hex.DecodeString(f.Keys["nostr_private_key"])
	require.NoError(t, err)
	owner, _ := btcec.PrivKeyFromBytes(keyBytes)
	require.Equal(t, f.Grant.Owner, Public(owner))
	require.Error(t, f.Grant.Validate(f.Grant.Origin, f.Grant.Publisher, 111), "append window expired")
	plain, err := Open(f.Record, owner)
	require.NoError(t, err, "historical encrypted records remain readable")
	require.Equal(t, f.BundleJSON, string(plain))
	require.Equal(t, f.Digests["plaintext"], Hash(plain))
	changedGrant := f.Grant
	changedGrant.MaxRecords--
	require.Error(t, Verify(changedGrant.Owner, changedGrant.Digest(), changedGrant.Signature))
	changedStore := f.Store
	changedStore.Bytes++
	require.Error(t, Verify(changedStore.Grant.Publisher, changedStore.Digest(), changedStore.Signature))
	changedFetch := f.Fetch
	changedFetch.After++
	require.Error(t, Verify(changedFetch.Owner, changedFetch.Digest(), changedFetch.Signature))
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}
