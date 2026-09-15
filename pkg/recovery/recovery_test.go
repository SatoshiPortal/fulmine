package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func testKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	k, e := btcec.NewPrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func testGrant(t *testing.T, owner *btcec.PrivateKey, publisher, origin string) Grant {
	t.Helper()
	now := uint64(time.Now().Unix())
	g := Grant{Owner: Public(owner), Publisher: publisher, Origin: origin, ID: Hash([]byte("test grant")), Scope: Hash([]byte("test intent")), ValidFrom: now - 10, ExpiresAt: now + 3600, MaxRecords: 16, MaxBytes: 2 * 1024 * 1024}
	var err error
	g.Signature, err = Sign(owner, g.Digest())
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestEncryptedEnvelope(t *testing.T) {
	user, publisher, other := testKey(t), testKey(t), testKey(t)
	grant := testGrant(t, user, Public(publisher), "http://127.0.0.1:9999")
	sealed, err := Seal(grant, publisher, []byte(`{"branch":"private-data"}`))
	if err != nil {
		t.Fatal(err)
	}
	record := Record{Grant: grant, Ciphertext: sealed.Ciphertext, Hash: sealed.Hash}
	plain, err := Open(record, user)
	if err != nil || !bytes.Contains(plain, []byte("private-data")) {
		t.Fatalf("open failed: %v", err)
	}
	if _, err = Open(record, other); err == nil {
		t.Fatal("wrong recipient decrypted")
	}
	if _, err = Open(record, publisher); err == nil {
		t.Fatal("publisher decrypted")
	}
	record.Hash = strings.Repeat("0", 64)
	if _, err = Open(record, user); err == nil {
		t.Fatal("modified hash accepted")
	}
	record.Hash = sealed.Hash
	record.Grant.Publisher = Public(other)
	if _, err = Open(record, user); err == nil {
		t.Fatal("substituted publisher accepted")
	}
	if _, err = Seal(grant, publisher, bytes.Repeat([]byte("x"), MaxPlaintext+1)); err == nil {
		t.Fatal("oversize bundle accepted")
	}
}

func TestOutboxLostReplyAndRestart(t *testing.T) {
	user := testKey(t)
	var uploads []StoreRequest
	fail := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request StoreRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		uploads = append(uploads, request)
		if fail {
			fail = false
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(Receipt{ID: 1, Hash: request.Hash})
	}))
	defer server.Close()
	dir := t.TempDir()
	m, err := NewManager(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	g := testGrant(t, user, m.Public(), server.URL)
	if err = m.Deliver(context.Background(), "intent", "batch", Registration{Grant: g}, []byte("branch")); err == nil {
		t.Fatal("failed upload passed gate")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = NewManager(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Deliver(context.Background(), "intent", "batch", Registration{Grant: g}, []byte("branch")); err != nil {
		t.Fatal(err)
	}
	if len(uploads) != 2 || uploads[0].Ciphertext != uploads[1].Ciphertext {
		t.Fatal("restart re-encrypted uncertain upload")
	}
	if err = m.Deliver(context.Background(), "intent", "batch", Registration{Grant: g}, []byte("changed branch")); err == nil {
		t.Fatal("changed batch accepted")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "outbox-") {
			raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			if bytes.Contains(raw, []byte(`"branch"`)) {
				t.Fatal("plaintext leaked into outbox")
			}
		}
	}
}

// A real Bitcoin signature fixture exercises the same exporter the Fulmine
// finalization callback uses. It does not simulate an arkd round.
func signedBranch(t *testing.T) (*tree.TxTree, *psbt.Packet, []byte) {
	t.Helper()
	key := testKey(t)
	script, err := txscript.PayToTaprootScript(key.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	parent := wire.NewMsgTx(2)
	parent.AddTxIn(&wire.TxIn{})
	parent.AddTxOut(wire.NewTxOut(10000, script))
	commit, err := psbt.NewFromUnsignedTx(parent)
	if err != nil {
		t.Fatal(err)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 0}, Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(wire.NewTxOut(10000, script))
	packet, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	prev := txscript.NewCannedPrevOutputFetcher(script, 10000)
	digest, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(tx, prev), txscript.SigHashDefault, tx, 0, prev)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(key, digest)
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[0].TaprootKeySpendSig = sig.Serialize()
	return &tree.TxTree{Root: packet}, commit, script
}
func TestBranchValidation(t *testing.T) {
	tree, commit, script := signedBranch(t)
	branch, _, err := ExtractBranch(tree, commit, script, 10000)
	if err != nil || len(branch) != 1 {
		t.Fatalf("valid branch rejected %v", err)
	}
	if _, _, err = ExtractBranch(tree, commit, script, 9999); err == nil {
		t.Fatal("wrong amount accepted")
	}
	tree.Root.Inputs[0].TaprootKeySpendSig[0] ^= 1
	if _, _, err = ExtractBranch(tree, commit, script, 10000); err == nil {
		t.Fatal("invalid signature accepted")
	}
	tree.Root.Inputs[0].TaprootKeySpendSig = nil
	if _, _, err = ExtractBranch(tree, commit, script, 10000); err == nil {
		t.Fatal("unsigned branch accepted")
	}
}

func TestBackupServerIntegration(t *testing.T) {
	binary := os.Getenv("BACKUP_PROTOTYPE_BIN")
	if binary == "" {
		t.Skip("set BACKUP_PROTOTYPE_BIN to the built Rust prototype")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "http://" + address
	m, err := NewManager(filepath.Join(t.TempDir(), "delegate"), origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	db := filepath.Join(t.TempDir(), "recovery.sqlite")
	start := func() *exec.Cmd {
		cmd := exec.Command(binary, db, address, origin, m.Public())
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			conn, e := net.DialTimeout("tcp", address, 20*time.Millisecond)
			if e == nil {
				conn.Close()
				return cmd
			}
			time.Sleep(20 * time.Millisecond)
		}
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("backup process did not start")
		return nil
	}
	command := start()
	defer func() { command.Process.Kill(); command.Wait() }()
	owner := testKey(t)
	grant := testGrant(t, owner, m.Public(), origin)
	// Capture and seal an actual signed Bitcoin branch with no fee funding.
	tree, commit, script := signedBranch(t)
	branch, outpoint, err := ExtractBranch(tree, commit, script, 10000)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"branch": branch, "outpoint": outpoint, "script": hex.EncodeToString(script)})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Deliver(context.Background(), "intent", "batch", Registration{Grant: grant}, payload); err != nil {
		t.Fatal(err)
	}
	if err = m.Deliver(context.Background(), "intent", "batch", Registration{Grant: grant}, payload); err != nil {
		t.Fatal(err)
	}
	// The delegate and backup can restart; retrieval only needs the owner key.
	command.Process.Kill()
	command.Wait()
	command = start()
	page, err := FetchPage(context.Background(), origin, owner, 0, 0)
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("fetch: %v %+v", err, page)
	}
	decrypted, err := Open(page.Records[0], owner)
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("restored payload mismatch: %v", err)
	}
	// Publisher signature and bare owner identity cannot authorize a fetch.
	forged := FetchRequest{Owner: Public(owner), Timestamp: uint64(time.Now().Unix())}
	forged.Signature, _ = Sign(m.key, forged.Digest())
	if err = Post(context.Background(), NewHTTPClient(), origin+"/api/v1/arkade-recovery-records/fetch", forged, new(Page)); err == nil {
		t.Fatal("publisher could fetch user's records")
	}
	forged.Signature = ""
	if err = Post(context.Background(), NewHTTPClient(), origin+"/api/v1/arkade-recovery-records/fetch", forged, new(Page)); err == nil {
		t.Fatal("unsigned fetch accepted")
	}
	other := testKey(t)
	otherPage, err := FetchPage(context.Background(), origin, other, 0, 0)
	if err != nil || len(otherPage.Records) != 0 {
		t.Fatal("cross-user data leak")
	}
	// Exercise pagination against real authenticated uploads and a fixed snapshot.
	for i := 0; i < 9; i++ {
		if err = m.Deliver(context.Background(), "intent", fmt.Sprint("batch", i), Registration{Grant: grant}, []byte(fmt.Sprint("candidate", i))); err != nil {
			t.Fatal(err)
		}
	}
	first, err := FetchPage(context.Background(), origin, owner, 0, 0)
	if err != nil || first.NextAfter == nil {
		t.Fatalf("missing next page %v", err)
	}
	if err = m.Deliver(context.Background(), "intent", "later", Registration{Grant: grant}, []byte("later")); err != nil {
		t.Fatal(err)
	}
	second, err := FetchPage(context.Background(), origin, owner, *first.NextAfter, first.Snapshot)
	if err != nil || len(first.Records)+len(second.Records) != 10 {
		t.Fatalf("unstable pagination %v", err)
	}
}
