package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Identity is this device's long-lived cryptographic identity. The Ed25519 key
// signs everything we say; the X25519 key establishes per-peer session
// secrets. The fingerprint of the Ed25519 public key IS our session id, so a
// session id cannot be claimed by anyone who doesn't hold the private key.
type Identity struct {
	EdPriv ed25519.PrivateKey
	EdPub  ed25519.PublicKey
	XPriv  *ecdh.PrivateKey
	XPub   *ecdh.PublicKey
	FP     string // 32 hex chars = first 16 bytes of SHA-256(EdPub)
}

type keyFile struct {
	Version int    `json:"version"`
	EdSeed  string `json:"ed25519_seed"`
	XPriv   string `json:"x25519_priv"`
	Created string `json:"created"`
}

// Fingerprint reduces a public key to the short, stable identifier shown
// everywhere in the UI.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SafetyNumber formats a fingerprint for humans to read aloud when verifying a
// contact out of band.
func SafetyNumber(fp string) string {
	up := strings.ToUpper(fp)
	var parts []string
	for i := 0; i+4 <= len(up); i += 4 {
		parts = append(parts, up[i:i+4])
	}
	return strings.Join(parts, "-")
}

// LoadOrCreateIdentity reads the key file, or generates and persists a new
// identity if none exists. The bool reports whether a new key was created.
func LoadOrCreateIdentity(path string) (*Identity, bool, error) {
	if b, err := os.ReadFile(path); err == nil {
		var kf keyFile
		if err := json.Unmarshal(b, &kf); err != nil {
			return nil, false, fmt.Errorf("identity file %s is corrupt: %w", path, err)
		}
		seed, err := base64.StdEncoding.DecodeString(kf.EdSeed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, false, fmt.Errorf("identity file %s has an unusable ed25519 seed", path)
		}
		xb, err := base64.StdEncoding.DecodeString(kf.XPriv)
		if err != nil {
			return nil, false, fmt.Errorf("identity file %s has an unusable x25519 key: %w", path, err)
		}
		xp, err := ecdh.X25519().NewPrivateKey(xb)
		if err != nil {
			return nil, false, fmt.Errorf("identity file %s has an unusable x25519 key: %w", path, err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		id := &Identity{
			EdPriv: priv,
			EdPub:  priv.Public().(ed25519.PublicKey),
			XPriv:  xp,
			XPub:   xp.PublicKey(),
		}
		id.FP = Fingerprint(id.EdPub)
		return id, false, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	xp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	kf := keyFile{
		Version: 2,
		EdSeed:  base64.StdEncoding.EncodeToString(priv.Seed()),
		XPriv:   base64.StdEncoding.EncodeToString(xp.Bytes()),
		Created: time.Now().Format(time.RFC3339),
	}
	blob, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, false, err
	}
	id := &Identity{EdPriv: priv, EdPub: pub, XPriv: xp, XPub: xp.PublicKey()}
	id.FP = Fingerprint(id.EdPub)
	return id, true, nil
}

// Sign produces a detached signature over a domain-separated payload.
func (id *Identity) Sign(payload string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(id.EdPriv, []byte(payload)))
}

// VerifySig checks a detached signature against a public key.
func VerifySig(pub ed25519.PublicKey, payload, sig string) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(payload), raw)
}

// ---------------------------------------------------------------- trust store

// TrustRecord is what we remember about a fingerprint between runs.
type TrustRecord struct {
	FP        string    `json:"fp"`
	Nick      string    `json:"nick"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Verified  bool      `json:"verified"`
	Sightings int       `json:"sightings"`
}

// TrustStore implements trust-on-first-use. The first time we see a
// fingerprint we record it; if that fingerprint ever changes for a name we
// already know, that is worth shouting about.
type TrustStore struct {
	path string
	mu   sync.Mutex
	recs map[string]*TrustRecord
}

func LoadTrustStore(path string) *TrustStore {
	t := &TrustStore{path: path, recs: map[string]*TrustRecord{}}
	if b, err := os.ReadFile(path); err == nil {
		var list []*TrustRecord
		if json.Unmarshal(b, &list) == nil {
			for _, r := range list {
				if r != nil && r.FP != "" {
					t.recs[r.FP] = r
				}
			}
		}
	}
	return t
}

func (t *TrustStore) save() {
	list := make([]*TrustRecord, 0, len(t.recs))
	for _, r := range t.recs {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].FP < list[j].FP })
	if b, err := json.MarshalIndent(list, "", "  "); err == nil {
		_ = os.MkdirAll(filepath.Dir(t.path), 0o700)
		_ = os.WriteFile(t.path, b, 0o600)
	}
}

// Observation is the verdict on a peer we just heard from.
type Observation struct {
	Status   string // new | known | renamed | impersonation
	PrevNick string
	OtherFP  string // the fingerprint that already owns this nick, if any
	Verified bool
}

// Observe records a sighting and reports anything suspicious about it.
func (t *TrustStore) Observe(fp, nick string) Observation {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Is this display name already bound to a different key we know?
	other := ""
	for f, r := range t.recs {
		if f != fp && strings.EqualFold(r.Nick, nick) {
			other = f
		}
	}

	r, ok := t.recs[fp]
	if !ok {
		r = &TrustRecord{FP: fp, Nick: nick, FirstSeen: time.Now()}
		t.recs[fp] = r
		r.LastSeen = time.Now()
		r.Sightings = 1
		t.save()
		st := "new"
		if other != "" {
			st = "impersonation"
		}
		return Observation{Status: st, OtherFP: other}
	}

	prev := r.Nick
	r.LastSeen = time.Now()
	r.Sightings++
	status := "known"
	if !strings.EqualFold(prev, nick) {
		r.Nick = nick
		status = "renamed"
	}
	if other != "" {
		status = "impersonation"
	}
	t.save()
	return Observation{Status: status, PrevNick: prev, OtherFP: other, Verified: r.Verified}
}

func (t *TrustStore) SetVerified(fp string, v bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.recs[fp]
	if !ok {
		return false
	}
	r.Verified = v
	t.save()
	return true
}

func (t *TrustStore) IsVerified(fp string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.recs[fp]
	return ok && r.Verified
}

func (t *TrustStore) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recs)
}
