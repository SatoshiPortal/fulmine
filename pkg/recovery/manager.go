package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/sys/unix"
)

// Registration is committed to the exact intent and output contract metadata.
type Registration struct {
	Grant           Grant             `json:"grant"`
	Outputs         []Output          `json:"outputs"`
	OwnerSignatures map[string]string `json:"owner_signatures"`
}
type Output struct {
	Script     string   `json:"script"`
	Tapscripts []string `json:"tapscripts"`
	KeyPath    string   `json:"key_path"`
}

func Scope(message, proof string, outputs []Output) string {
	raw, _ := json.Marshal(outputs)
	return hex.EncodeToString(Digest(Domain, "scope", message, proof, string(raw)))
}

type Manager struct {
	dir, origin string
	key         *btcec.PrivateKey
	client      *http.Client
	guard       chan struct{}
	lockFile    *os.File
	closed      bool
	public      string
}

func NewManager(dir, origin string) (*Manager, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && u.Hostname() == "127.0.0.1") {
		return nil, errors.New("recovery origin must be HTTPS (or loopback HTTP for prototype)")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lockFile, err := os.OpenFile(filepath.Join(dir, "publisher.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("recovery directory already owned: %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			lockFile.Close()
		}
	}()
	legacy, err := filepath.Glob(filepath.Join(dir, "registration-*.json"))
	if err != nil {
		return nil, err
	}
	if len(legacy) != 0 {
		return nil, errors.New("legacy registration sidecars found; retain this directory for recovery and use a fresh regtest directory")
	}
	keyPath := filepath.Join(dir, "publisher.key")
	raw, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		k, e := btcec.NewPrivateKey()
		if e != nil {
			return nil, e
		}
		raw = k.Serialize()
		k.Zero()
		if err = atomicWrite(keyPath, raw); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("invalid stored publisher key")
	}
	defer clear(raw)
	k, _ := btcec.PrivKeyFromBytes(raw)
	if k.Key.IsZero() || !bytes.Equal(k.Serialize(), raw) {
		k.Zero()
		return nil, errors.New("invalid zero publisher key")
	}
	ready = true
	return &Manager{dir: dir, origin: origin, key: k, public: Public(k), client: NewHTTPClient(), lockFile: lockFile, guard: make(chan struct{}, 1)}, nil
}
func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("recovery redirects disabled") }}
}
func (m *Manager) Public() string { return m.public }
func (m *Manager) Origin() string { return m.origin }

// Close waits for the bounded in-flight delivery, erases the publisher key and
// releases process ownership. Wallet lock/unlock does not close the manager.
func (m *Manager) Close() error {
	m.guard <- struct{}{}
	defer func() { <-m.guard }()
	if m.closed {
		return nil
	}
	m.closed = true
	m.key.Zero()
	m.client.CloseIdleConnections()
	return m.lockFile.Close()
}
func (m *Manager) acquire(ctx context.Context) error {
	select {
	case m.guard <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if m.closed {
		<-m.guard
		return errors.New("recovery manager closed")
	}
	if err := ctx.Err(); err != nil {
		<-m.guard
		return err
	}
	return nil
}
func (m *Manager) release() { <-m.guard }

// atomicWrite syncs file contents and the parent directory before success.
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".recovery-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func ParseRegistration(raw string) (Registration, error) {
	var r Registration
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing registration data")
	}
	return r, nil
}

type outbox struct {
	Request       StoreRequest `json:"request"`
	PlaintextHash string       `json:"plaintext_hash"`
}

// Deliver returns only after the backup acknowledges the exact ciphertext hash
// and that acknowledgement is persisted. Lost replies retry identical ciphertext.
func (m *Manager) Deliver(ctx context.Context, intentID, batchID string, r Registration, plain []byte) error {
	_, err := m.DeliverReceipt(ctx, intentID, batchID, r, plain)
	return err
}
func (m *Manager) DeliverReceipt(ctx context.Context, intentID, batchID string, r Registration, plain []byte) (Receipt, error) {
	if err := m.acquire(ctx); err != nil {
		return Receipt{}, err
	}
	defer m.release()
	path := filepath.Join(m.dir, "outbox-"+hex.EncodeToString(Digest(intentID, batchID))+".json")
	var box outbox
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = r.Grant.Validate(m.origin, m.Public(), uint64(time.Now().Unix())); err != nil {
			return Receipt{}, err
		}
		req, e := Seal(r.Grant, m.key, plain)
		if e != nil {
			return Receipt{}, e
		}
		box = outbox{Request: req, PlaintextHash: Hash(plain)}
		if err = saveBox(path, box); err != nil {
			return Receipt{}, err
		}
	} else if err != nil {
		return Receipt{}, err
	} else if err = json.Unmarshal(raw, &box); err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(box.Request.Grant.Digest(), r.Grant.Digest()) || box.PlaintextHash != Hash(plain) {
		return Receipt{}, errors.New("batch recovery data changed after sealing")
	}
	// Reconfirm storage even after a previous ack. This avoids treating a local
	// receipt as evidence the remote database is still available after rollback.
	box.Request.Timestamp = uint64(time.Now().Unix())
	box.Request.Signature, err = Sign(m.key, box.Request.Digest())
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err = Post(ctx, m.client, m.origin+"/api/v1/arkade-recovery-records", box.Request, &receipt); err != nil {
		return Receipt{}, err
	}
	if receipt.ID <= 0 || receipt.Hash != box.Request.Hash {
		return Receipt{}, errors.New("backup receipt mismatch")
	}
	if err := saveBox(path, box); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}
func saveBox(path string, box outbox) error {
	raw, err := json.Marshal(box)
	if err != nil {
		return err
	}
	return atomicWrite(path, raw)
}
func Post(ctx context.Context, c *http.Client, endpoint string, value, result any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("backup HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil {
		return err
	}
	if len(body) > 2*1024*1024 {
		return errors.New("backup response too large")
	}
	return json.Unmarshal(body, result)
}

// FetchPage requires the user's private key; the publisher has no read grant.
func FetchPage(ctx context.Context, origin string, owner *btcec.PrivateKey, after, snapshot uint64) (Page, error) {
	request := FetchRequest{Owner: Public(owner), After: after, Snapshot: snapshot, Timestamp: uint64(time.Now().Unix())}
	var err error
	request.Signature, err = Sign(owner, request.Digest())
	if err != nil {
		return Page{}, err
	}
	var page Page
	err = Post(ctx, NewHTTPClient(), origin+"/api/v1/arkade-recovery-records/fetch", request, &page)
	return page, err
}
