package application

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/fulmine/pkg/recovery"
	"github.com/ArkLabsHQ/fulmine/test/recovery/fixtures"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/stretchr/testify/require"
)

func TestRecoveryBundleWireConformance(t *testing.T) {
	var f struct {
		Bundle     json.RawMessage   `json:"bundle"`
		BundleJSON string            `json:"bundle_json"`
		Digests    map[string]string `json:"digests"`
	}
	require.NoError(t, json.Unmarshal(fixtures.WireV1, &f))
	var bundle recoveryBundle
	require.NoError(t, json.Unmarshal(f.Bundle, &bundle))
	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	require.Equal(t, f.BundleJSON, string(encoded), "application changes must not silently change persisted bundle bytes")
	require.JSONEq(t, string(f.Bundle), f.BundleJSON)
	require.Equal(t, 1, bundle.Version)
	require.Equal(t, "regtest", bundle.Network)
	require.Equal(t, f.Digests["scope"], recovery.Scope(bundle.Intent.Message, bundle.Intent.Proof, bundle.Registration.Outputs))
	for owner, signature := range bundle.Registration.OwnerSignatures {
		require.NoError(t, recovery.Verify(owner, bundle.Registration.Grant.Digest(), signature))
	}
	commit, err := psbt.NewFromRawBytes(strings.NewReader(bundle.Commitment), true)
	require.NoError(t, err)
	require.Equal(t, bundle.CommitmentTxID, commit.UnsignedTx.TxID())
	require.Len(t, bundle.Branch, 1)
	packet, err := psbt.NewFromRawBytes(strings.NewReader(bundle.Branch[0]), true)
	require.NoError(t, err)
	output, err := hex.DecodeString(bundle.Registration.Outputs[0].Script)
	require.NoError(t, err)
	branch, outpoint, err := recovery.ExtractBranch(&tree.TxTree{Root: packet}, commit, output, 10000)
	require.NoError(t, err)
	require.Equal(t, bundle.Branch, branch)
	require.Equal(t, bundle.Replacement, outpoint)
}
