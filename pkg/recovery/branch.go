package recovery

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// ExtractBranch matches one exact output and exports only its ancestry.
// Every node is verified against its actual parent output, including the
// commitment, rather than trusting signature events or PSBT witness metadata.
func ExtractBranch(t *tree.TxTree, commit *psbt.Packet, script []byte, amount int64) ([]string, string, error) {
	if t == nil || commit == nil || commit.UnsignedTx == nil || len(commit.UnsignedTx.TxOut) == 0 || amount <= 0 {
		return nil, "", fmt.Errorf("invalid recovery tree or commitment")
	}
	var branch []string
	var outpoint string
	matches := 0
	seen := make(map[string]bool)
	var walk func(*tree.TxTree, *wire.MsgTx, uint32, []string) error
	walk = func(node *tree.TxTree, parent *wire.MsgTx, index uint32, path []string) error {
		if node == nil || node.Root == nil || node.Root.UnsignedTx == nil {
			return fmt.Errorf("missing tree node")
		}
		packet := node.Root
		tx := packet.UnsignedTx
		if seen[tx.TxID()] || len(seen) >= 512 {
			return fmt.Errorf("duplicate or oversized tree")
		}
		seen[tx.TxID()] = true
		if int(index) >= len(parent.TxOut) || len(tx.TxIn) != 1 || len(packet.Inputs) != 1 || len(tx.TxOut) == 0 || len(packet.Inputs[0].TaprootKeySpendSig) != 64 {
			return fmt.Errorf("unsigned or malformed tree node")
		}
		expected := wire.OutPoint{Hash: parent.TxHash(), Index: index}
		if tx.TxIn[0].PreviousOutPoint != expected {
			return fmt.Errorf("broken tree ancestry")
		}
		prev := parent.TxOut[index]
		sum := int64(0)
		for _, o := range tx.TxOut {
			if o.Value < 0 || o.Value > prev.Value || sum > prev.Value-o.Value {
				return fmt.Errorf("invalid tree output amount")
			}
			sum += o.Value
		}
		if sum != prev.Value {
			return fmt.Errorf("tree value mismatch")
		}
		signed := tx.Copy()
		signed.TxIn[0].Witness = wire.TxWitness{packet.Inputs[0].TaprootKeySpendSig}
		fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
		engine, err := txscript.NewEngine(prev.PkScript, signed, 0, txscript.StandardVerifyFlags, nil, txscript.NewTxSigHashes(signed, fetcher), prev.Value, fetcher)
		if err != nil {
			return err
		}
		if err = engine.Execute(); err != nil {
			return fmt.Errorf("invalid tree signature: %w", err)
		}
		encoded, err := packet.B64Encode()
		if err != nil {
			return err
		}
		path = append(append([]string(nil), path...), encoded)
		for i, o := range tx.TxOut {
			if bytes.Equal(o.PkScript, script) && o.Value == amount {
				if len(node.Children) != 0 {
					return fmt.Errorf("replacement must be a leaf output")
				}
				matches++
				branch = path
				outpoint = fmt.Sprintf("%s:%d", tx.TxID(), i)
			}
		}
		indexes := make([]int, 0, len(node.Children))
		for i := range node.Children {
			indexes = append(indexes, int(i))
		}
		sort.Ints(indexes)
		for _, i := range indexes {
			if err = walk(node.Children[uint32(i)], tx, uint32(i), path); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(t, commit.UnsignedTx, 0, nil); err != nil {
		return nil, "", err
	}
	if matches != 1 {
		return nil, "", fmt.Errorf("expected one replacement output, found %d", matches)
	}
	return branch, outpoint, nil
}
