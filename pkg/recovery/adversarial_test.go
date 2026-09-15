package recovery

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestEnvelopeTamperingMatrix(t *testing.T) {
	owner, publisher := testKey(t), testKey(t)
	g := testGrant(t, owner, Public(publisher), "https://backup.example")
	sealed, err := Seal(g, publisher, []byte("recovery candidate"))
	require.NoError(t, err)
	for _, mode := range []string{"content", "event_id", "event_signature", "publisher_signature", "recipient", "grant_tag", "extra_tag", "missing_tag", "event_kind", "event_pubkey", "event_time", "grant_scope", "grant_signature", "base64_whitespace", "unknown_field", "trailing_json"} {
		t.Run(mode, func(t *testing.T) {
			record := Record{Grant: g, Hash: sealed.Hash, Ciphertext: sealed.Ciphertext}
			raw, err := base64.StdEncoding.DecodeString(record.Ciphertext)
			require.NoError(t, err)
			var e Envelope
			require.NoError(t, json.Unmarshal(raw, &e))
			switch mode {
			case "content":
				e.Event.Content = "broken"
			case "event_id":
				e.Event.ID = strings.Repeat("0", 64)
			case "event_signature":
				e.Event.Sig = strings.Repeat("0", 128)
			case "publisher_signature":
				e.PublisherSignature = strings.Repeat("0", 128)
			case "recipient":
				e.Event.Tags[0][1] = Public(publisher)
			case "grant_tag":
				e.Event.Tags[1][1] = strings.Repeat("0", 64)
			case "extra_tag":
				e.Event.Tags = append(e.Event.Tags, []string{"extra", "tag"})
			case "missing_tag":
				e.Event.Tags = nil
			case "event_kind":
				e.Event.Kind++
			case "event_pubkey":
				e.Event.PubKey = Public(publisher)
			case "event_time":
				e.Event.CreatedAt++
			case "grant_scope":
				record.Grant.Scope = strings.Repeat("0", 64)
			case "grant_signature":
				record.Grant.Signature = ""
			}
			raw, err = json.Marshal(e)
			require.NoError(t, err)
			if mode == "unknown_field" {
				raw = append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)
			}
			if mode == "trailing_json" {
				raw = append(raw, []byte(`{}`)...)
			}
			record.Hash = Hash(raw)
			record.Ciphertext = base64.StdEncoding.EncodeToString(raw)
			if mode == "base64_whitespace" {
				record.Ciphertext += "\n"
			}
			_, err = Open(record, owner)
			require.Error(t, err)
		})
	}
}
func TestEnvelopeAuthenticatedBadCiphertext(t *testing.T) {
	owner, publisher, sender := testKey(t), testKey(t), testKey(t)
	g := testGrant(t, owner, Public(publisher), "https://backup.example")
	event := Event{PubKey: Public(sender), CreatedAt: time.Now().Unix(), Kind: 30078, Tags: [][]string{{"p", g.Owner}, {"d", g.ID}}, Content: "invalid NIP44 ciphertext"}
	digest, err := event.digest()
	require.NoError(t, err)
	event.ID = hex.EncodeToString(digest)
	event.Sig, err = Sign(sender, digest)
	require.NoError(t, err)
	sig, err := Sign(publisher, attestation(g, event.ID))
	require.NoError(t, err)
	raw, err := json.Marshal(Envelope{Event: event, PublisherSignature: sig})
	require.NoError(t, err)
	_, err = Open(Record{Grant: g, Hash: Hash(raw), Ciphertext: base64.StdEncoding.EncodeToString(raw)}, owner)
	require.ErrorContains(t, err, "decrypt recovery")
}
func TestEnvelopeHistoricalAndSizeBoundaries(t *testing.T) {
	owner, publisher := testKey(t), testKey(t)
	g := testGrant(t, owner, Public(publisher), "https://backup.example")
	g.ValidFrom = 1
	g.ExpiresAt = 2
	var err error
	g.Signature, err = Sign(owner, g.Digest())
	require.NoError(t, err)
	for _, size := range []int{1, MaxPlaintext} {
		plain := bytes.Repeat([]byte("x"), size)
		sealed, err := Seal(g, publisher, plain)
		require.NoError(t, err)
		opened, err := Open(Record{Grant: g, Hash: sealed.Hash, Ciphertext: sealed.Ciphertext}, owner)
		require.NoError(t, err)
		require.Equal(t, plain, opened)
	}
	for _, size := range []int{0, MaxPlaintext + 1} {
		_, err := Seal(g, publisher, bytes.Repeat([]byte("x"), size))
		require.Error(t, err)
	}
	require.Error(t, g.Validate(g.Origin, g.Publisher, uint64(time.Now().Unix())))
}
func TestBranchAdversarialMatrix(t *testing.T) {
	for _, mode := range []string{"nil_tree", "nil_commitment", "broken_parent", "missing_input", "extra_input", "missing_output", "negative_amount", "inflated_amount", "changed_script", "missing_signature", "changed_signature", "duplicate_node", "wrong_destination", "wrong_expected_amount"} {
		t.Run(mode, func(t *testing.T) {
			branch, commit, script := signedBranch(t)
			amount := int64(10000)
			switch mode {
			case "nil_tree":
				branch = nil
			case "nil_commitment":
				commit = nil
			case "broken_parent":
				branch.Root.UnsignedTx.TxIn[0].PreviousOutPoint.Index++
			case "missing_input":
				branch.Root.UnsignedTx.TxIn = nil
			case "extra_input":
				branch.Root.UnsignedTx.TxIn = append(branch.Root.UnsignedTx.TxIn, branch.Root.UnsignedTx.TxIn[0])
			case "missing_output":
				branch.Root.UnsignedTx.TxOut = nil
			case "negative_amount":
				branch.Root.UnsignedTx.TxOut[0].Value = -1
			case "inflated_amount":
				branch.Root.UnsignedTx.TxOut[0].Value++
			case "changed_script":
				branch.Root.UnsignedTx.TxOut[0].PkScript[2] ^= 1
			case "missing_signature":
				branch.Root.Inputs[0].TaprootKeySpendSig = nil
			case "changed_signature":
				branch.Root.Inputs[0].TaprootKeySpendSig[0] ^= 1
			case "duplicate_node":
				branch.Children = map[uint32]*tree.TxTree{0: branch}
			case "wrong_destination":
				script = []byte{0x51}
			case "wrong_expected_amount":
				amount--
			}
			_, _, err := ExtractBranch(branch, commit, script, amount)
			require.Error(t, err)
		})
	}
}

func FuzzRecoveryRecord(f *testing.F) {
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	owner, _ := btcec.PrivKeyFromBytes(keyBytes)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"ciphertext":"%%%"}`))
	f.Add([]byte(`{"grant":{"owner":"00"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 256*1024 {
			return
		}
		var r Record
		if json.Unmarshal(raw, &r) == nil {
			_, _ = Open(r, owner)
		}
	})
}
