// Package recovery implements the experimental Bull recovery wire contract.
// This protocol is intentionally domain-separated from production wallet backups.
package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

const Domain = "bullbitcoin-arkade-recovery-prototype-v1"
const MaxPlaintext = 60 * 1024

type Grant struct {
	Owner      string `json:"owner"`
	Publisher  string `json:"publisher"`
	Origin     string `json:"origin"`
	ID         string `json:"id"`
	Scope      string `json:"scope"`
	ValidFrom  uint64 `json:"valid_from"`
	ExpiresAt  uint64 `json:"expires_at"`
	MaxRecords uint64 `json:"max_records"`
	MaxBytes   uint64 `json:"max_bytes"`
	Signature  string `json:"signature"`
}
type StoreRequest struct {
	Grant      Grant  `json:"grant"`
	Ciphertext string `json:"ciphertext"`
	Hash       string `json:"ciphertext_sha256"`
	Bytes      uint64 `json:"ciphertext_bytes"`
	Timestamp  uint64 `json:"timestamp"`
	Signature  string `json:"signature"`
}
type FetchRequest struct {
	Owner     string `json:"owner"`
	After     uint64 `json:"after"`
	Snapshot  uint64 `json:"snapshot"`
	Timestamp uint64 `json:"timestamp"`
	Signature string `json:"signature"`
}
type Receipt struct {
	ID   int64  `json:"id"`
	Hash string `json:"ciphertext_sha256"`
}
type Record struct {
	ID         int64  `json:"id"`
	Grant      Grant  `json:"grant"`
	Ciphertext string `json:"ciphertext"`
	Hash       string `json:"ciphertext_sha256"`
}
type Page struct {
	Records   []Record `json:"records"`
	Snapshot  uint64   `json:"snapshot"`
	NextAfter *uint64  `json:"next_after"`
}

// UnmarshalJSON requires all pagination fields: missing metadata is not an empty snapshot.
func (p *Page) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Records   *[]Record       `json:"records"`
		Snapshot  *uint64         `json:"snapshot"`
		NextAfter json.RawMessage `json:"next_after"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if wire.Records == nil || wire.Snapshot == nil || len(wire.NextAfter) == 0 {
		return errors.New("incomplete recovery page")
	}
	var next *uint64
	if err := json.Unmarshal(wire.NextAfter, &next); err != nil {
		return err
	}
	*p = Page{Records: *wire.Records, Snapshot: *wire.Snapshot, NextAfter: next}
	return nil
}

func Hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func Digest(parts ...string) []byte {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return h[:]
}
func decimal(n uint64) string { return strconv.FormatUint(n, 10) }
func (g Grant) Digest() []byte {
	return Digest(Domain, "grant", g.Owner, g.Publisher, g.Origin, g.ID, g.Scope, decimal(g.ValidFrom), decimal(g.ExpiresAt), decimal(g.MaxRecords), decimal(g.MaxBytes))
}
func (s StoreRequest) Digest() []byte {
	return Digest(Domain, "store", hex.EncodeToString(s.Grant.Digest()), s.Hash, decimal(s.Bytes), decimal(s.Timestamp))
}
func (f FetchRequest) Digest() []byte {
	return Digest(Domain, "fetch", f.Owner, decimal(f.After), decimal(f.Snapshot), decimal(f.Timestamp))
}
func Public(k *btcec.PrivateKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
}
func Sign(k *btcec.PrivateKey, digest []byte) (string, error) {
	sig, err := schnorr.Sign(k, digest)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}
func Verify(pub string, digest []byte, signature string) error {
	p, err := hex.DecodeString(pub)
	if err != nil || hex.EncodeToString(p) != pub {
		return errors.New("invalid public key encoding")
	}
	key, err := schnorr.ParsePubKey(p)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(signature)
	if err != nil || hex.EncodeToString(b) != signature {
		return errors.New("invalid signature encoding")
	}
	sig, err := schnorr.ParseSignature(b)
	if err != nil {
		return err
	}
	if !sig.Verify(digest, key) {
		return errors.New("invalid signature")
	}
	return nil
}
func (g Grant) Validate(origin, publisher string, now uint64) error {
	if g.Origin != origin || g.Publisher != publisher || strings.ContainsRune(g.Origin, 0) || g.MaxRecords == 0 || g.MaxRecords > 16 || g.MaxBytes == 0 || g.MaxBytes > 2*1024*1024 || g.ExpiresAt <= g.ValidFrom || g.ExpiresAt-g.ValidFrom > 32*86400 || now < g.ValidFrom || now > g.ExpiresAt {
		return errors.New("invalid or expired recovery grant")
	}
	for _, v := range []string{g.ID, g.Scope} {
		b, e := hex.DecodeString(v)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != v {
			return errors.New("invalid grant digest encoding")
		}
	}
	return Verify(g.Owner, g.Digest(), g.Signature)
}

// Event is a NIP-01 signed event. NIP-44 ciphertext must have this signature.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func (e Event) digest() ([]byte, error) {
	b, err := json.Marshal([]any{0, e.PubKey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

type Envelope struct {
	Event              Event  `json:"event"`
	PublisherSignature string `json:"publisher_signature"`
}

func attestation(g Grant, id string) []byte {
	return Digest(Domain, "sealed", g.Owner, hex.EncodeToString(g.Digest()), id)
}

// Seal uses an ephemeral sender key. Persist only the returned bytes, not that key.
func Seal(g Grant, publisher *btcec.PrivateKey, plain []byte) (StoreRequest, error) {
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return StoreRequest{}, errors.New("recovery bundle exceeds prototype plaintext limit")
	}
	if Public(publisher) != g.Publisher {
		return StoreRequest{}, errors.New("publisher mismatch")
	}
	ephemeral, err := btcec.NewPrivateKey()
	if err != nil {
		return StoreRequest{}, err
	}
	defer ephemeral.Zero()
	conversation, err := nip44.GenerateConversationKey(g.Owner, hex.EncodeToString(ephemeral.Serialize()))
	if err != nil {
		return StoreRequest{}, err
	}
	content, err := nip44.Encrypt(string(plain), conversation)
	clear(conversation[:])
	if err != nil {
		return StoreRequest{}, err
	}
	event := Event{PubKey: Public(ephemeral), CreatedAt: time.Now().Unix(), Kind: 30078, Tags: [][]string{{"p", g.Owner}, {"d", g.ID}}, Content: content}
	digest, err := event.digest()
	if err != nil {
		return StoreRequest{}, err
	}
	event.ID = hex.EncodeToString(digest)
	event.Sig, err = Sign(ephemeral, digest)
	if err != nil {
		return StoreRequest{}, err
	}
	sig, err := Sign(publisher, attestation(g, event.ID))
	if err != nil {
		return StoreRequest{}, err
	}
	raw, err := json.Marshal(Envelope{event, sig})
	if err != nil {
		return StoreRequest{}, err
	}
	return StoreRequest{Grant: g, Ciphertext: base64.StdEncoding.EncodeToString(raw), Hash: Hash(raw), Bytes: uint64(len(raw))}, nil
}

// authenticateRecord verifies the public envelope without requiring the recipient's key.
// The publisher uses the same checks before retrying an outbox recovered from disk.
func authenticateRecord(record Record) (Event, error) {
	if err := record.Grant.Validate(record.Grant.Origin, record.Grant.Publisher, record.Grant.ValidFrom); err != nil {
		return Event{}, err
	}
	if len(record.Ciphertext) > 192*1024 {
		return Event{}, errors.New("record too large")
	}
	raw, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return Event{}, err
	}
	if len(raw) > 128*1024 || base64.StdEncoding.EncodeToString(raw) != record.Ciphertext || Hash(raw) != record.Hash {
		return Event{}, errors.New("ciphertext hash mismatch")
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&envelope); err != nil {
		return Event{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Event{}, errors.New("trailing envelope data")
	}
	event := envelope.Event
	digest, err := event.digest()
	if err != nil {
		return Event{}, err
	}
	if event.ID != hex.EncodeToString(digest) || event.Kind != 30078 || len(event.Tags) != 2 || len(event.Tags[0]) != 2 || len(event.Tags[1]) != 2 || event.Tags[0][0] != "p" || event.Tags[0][1] != record.Grant.Owner || event.Tags[1][0] != "d" || event.Tags[1][1] != record.Grant.ID {
		return Event{}, errors.New("invalid event binding")
	}
	if err = Verify(event.PubKey, digest, event.Sig); err != nil {
		return Event{}, err
	}
	if err = Verify(record.Grant.Publisher, attestation(record.Grant, event.ID), envelope.PublisherSignature); err != nil {
		return Event{}, err
	}
	return event, nil
}

// Open authenticates the user grant, publisher and ephemeral event before decrypting.
// Historical grants remain valid evidence after their append window expires.
func Open(record Record, owner *btcec.PrivateKey) ([]byte, error) {
	if record.Grant.Owner != Public(owner) {
		return nil, errors.New("recipient mismatch")
	}
	event, err := authenticateRecord(record)
	if err != nil {
		return nil, err
	}
	conversation, err := nip44.GenerateConversationKey(event.PubKey, hex.EncodeToString(owner.Serialize()))
	if err != nil {
		return nil, err
	}
	plain, err := nip44.Decrypt(event.Content, conversation)
	clear(conversation[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt recovery: %w", err)
	}
	if len(plain) > MaxPlaintext {
		return nil, errors.New("plaintext too large")
	}
	return []byte(plain), nil
}
