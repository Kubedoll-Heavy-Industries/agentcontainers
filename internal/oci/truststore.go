package oci

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// OrgKeyEntry represents a single trusted org public key in the trust store.
type OrgKeyEntry struct {
	// KeyID is the hex-encoded SHA-256 fingerprint of the raw Ed25519 public key bytes.
	KeyID string `json:"keyid"`
	// PublicKey is the raw 32-byte Ed25519 public key, base64-encoded.
	PublicKey []byte `json:"publicKey"`
	// Comment is an optional human-readable label.
	Comment string `json:"comment,omitempty"`
}

// OrgTrustStore is the on-disk representation of ~/.agentcontainers/trusted-org-keys.json.
type OrgTrustStore struct {
	Keys []OrgKeyEntry `json:"keys"`
}

// DefaultTrustStorePath returns the default path for the org trust store,
// honouring the AC_ORG_TRUST_STORE env var or falling back to
// ~/.agentcontainers/trusted-org-keys.json.
func DefaultTrustStorePath() (string, error) {
	if v := os.Getenv("AC_ORG_TRUST_STORE"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("looking up home directory: %w", err)
	}
	return filepath.Join(home, ".agentcontainers", "trusted-org-keys.json"), nil
}

// LoadTrustStore reads the trust store from path. If the file does not exist,
// an empty (but non-nil) trust store is returned so callers can treat a missing
// store as "no trusted keys" rather than an error.
func LoadTrustStore(path string) (*OrgTrustStore, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &OrgTrustStore{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading trust store %s: %w", path, err)
	}

	var ts OrgTrustStore
	if err := json.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("parsing trust store %s: %w", path, err)
	}
	return &ts, nil
}

// SaveTrustStore writes the trust store atomically (write to temp, rename).
func SaveTrustStore(path string, ts *OrgTrustStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating trust store directory: %w", err)
	}
	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling trust store: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing trust store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("committing trust store: %w", err)
	}
	return nil
}

// TrustedKeys converts the trust store into a map[keyid]→PublicKey for
// use in VerifyDescriptor.
func (ts *OrgTrustStore) TrustedKeys() (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(ts.Keys))
	for _, e := range ts.Keys {
		if len(e.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust store entry %q has invalid key length %d (want %d)",
				e.KeyID, len(e.PublicKey), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(e.PublicKey)
		// Verify keyid matches.
		if got := OrgKeyID(pub); got != e.KeyID {
			return nil, fmt.Errorf("trust store entry keyid mismatch: stored %q, computed %q", e.KeyID, got)
		}
		out[e.KeyID] = pub
	}
	return out, nil
}

// AddKey adds an Ed25519 public key to the trust store (no-op if already present).
// Returns the key ID.
func (ts *OrgTrustStore) AddKey(pub ed25519.PublicKey, comment string) string {
	keyID := OrgKeyID(pub)
	for _, e := range ts.Keys {
		if e.KeyID == keyID {
			return keyID // already present
		}
	}
	ts.Keys = append(ts.Keys, OrgKeyEntry{
		KeyID:     keyID,
		PublicKey: pub,
		Comment:   comment,
	})
	return keyID
}

// LoadTrustStoreDefault loads the trust store from the default path.
// Returns an empty store (not an error) if the file does not exist.
func LoadTrustStoreDefault() (*OrgTrustStore, error) {
	path, err := DefaultTrustStorePath()
	if err != nil {
		return nil, err
	}
	return LoadTrustStore(path)
}
