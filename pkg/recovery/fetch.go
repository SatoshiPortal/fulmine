package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
)

type fetchManifest struct {
	Version  int               `json:"version"`
	Owner    string            `json:"owner"`
	Origin   string            `json:"origin"`
	Snapshot uint64            `json:"snapshot"`
	After    uint64            `json:"after"`
	Complete bool              `json:"complete"`
	Files    map[string]string `json:"files"` // ciphertext hash -> plaintext hash
}

// FetchToDirectory resumes one authenticated snapshot. On error, the directory
// contains explicitly incomplete results; successfully written bundles survive.
// A completed directory can be refreshed to a new snapshot on the next call.
func FetchToDirectory(ctx context.Context, origin string, owner *btcec.PrivateKey, dir string) (int, error) {
	if err := validateOrigin(origin); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, err
	}
	path := filepath.Join(dir, "manifest.json")
	m := fetchManifest{Version: 1, Owner: Public(owner), Origin: origin, Files: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(raw, &m); err != nil {
			return 0, err
		}
		if m.Version != 1 || m.Owner != Public(owner) || m.Origin != origin || m.Files == nil || len(m.Files) > 10000 {
			return 0, fmt.Errorf("fetch manifest does not match owner/origin or supported limits")
		}
		for hash, plainHash := range m.Files {
			if !validFileHash(hash) || !validFileHash(plainHash) {
				return 0, fmt.Errorf("invalid candidate filename")
			}
			raw, err := os.ReadFile(filepath.Join(dir, hash+".json"))
			if err != nil {
				return 0, err
			}
			if Hash(raw) != plainHash {
				return 0, fmt.Errorf("saved candidate was modified")
			}
		}
		if m.Complete {
			m.After = 0
			m.Snapshot = 0
			m.Complete = false
		}
	} else if !os.IsNotExist(err) {
		return 0, err
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return 0, err
		}
		if len(entries) > 0 {
			return 0, fmt.Errorf("nonempty fetch directory has no manifest")
		}
	}
	save := func() error {
		raw, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return atomicWrite(path, raw)
	}
	if err := save(); err != nil {
		return len(m.Files), err
	}
	for {
		page, err := FetchPage(ctx, origin, owner, m.After, m.Snapshot)
		if err != nil {
			return len(m.Files), fmt.Errorf("incomplete fetch; resume this directory: %w", err)
		}
		if m.Snapshot != 0 && page.Snapshot != m.Snapshot {
			return len(m.Files), fmt.Errorf("server changed snapshot")
		}
		if page.Snapshot < m.After {
			return len(m.Files), fmt.Errorf("snapshot precedes cursor")
		}
		last := m.After
		for _, record := range page.Records {
			if record.ID <= 0 || uint64(record.ID) <= last || uint64(record.ID) > page.Snapshot {
				return len(m.Files), fmt.Errorf("invalid record order")
			}
			last = uint64(record.ID)
			if record.Grant.Origin != origin {
				return len(m.Files), fmt.Errorf("record has different backup origin")
			}
			plain, err := Open(record, owner)
			if err != nil {
				return len(m.Files), err
			}
			file := filepath.Join(dir, record.Hash+".json")
			prior, err := os.ReadFile(file)
			if err == nil {
				if !bytes.Equal(prior, plain) {
					clear(plain)
					return len(m.Files), fmt.Errorf("candidate file conflicts with authenticated record")
				}
			} else if os.IsNotExist(err) {
				if len(m.Files) >= 10000 {
					clear(plain)
					return len(m.Files), fmt.Errorf("fetch record limit reached")
				}
				if err = atomicWrite(file, plain); err != nil {
					clear(plain)
					return len(m.Files), err
				}
			} else {
				clear(plain)
				return len(m.Files), err
			}
			m.Files[record.Hash] = Hash(plain)
			clear(plain)
		}
		m.Snapshot = page.Snapshot
		if page.NextAfter == nil {
			if last != page.Snapshot {
				return len(m.Files), fmt.Errorf("incomplete final recovery page")
			}
			m.Complete = true
		} else {
			if last <= m.After || *page.NextAfter != last || last >= page.Snapshot {
				return len(m.Files), fmt.Errorf("non-progressing pagination")
			}
			m.After = last
		}
		if err = save(); err != nil {
			return len(m.Files), err
		}
		if m.Complete {
			return len(m.Files), nil
		}
	}
}
func validFileHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
