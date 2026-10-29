// Package certpair makes a customer server order ONE certificate covering both
// of its origins, the app name and files.<app name>, instead of one per name.
//
// CertMagic issues a certificate per managed subject and offers no hook on the
// CSR it signs, so the pair is assembled from two of its documented extension
// points: a KeyGenerator that remembers the key it made, and an Issuer that
// re-signs a wider CSR with that key before the ACME exchange.
package certpair

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/caddyserver/certmagic"
)

// recorderCapacity bounds the map. CertMagic asks for one key per obtain or
// per renew and hands the matching CSR to the issuer immediately afterwards,
// so only the newest entries are ever read; the rest are retries and the
// separate IP certificate.
const recorderCapacity = 8

// KeyRecorder generates private keys for CertMagic and remembers them by their
// public half. An Issuer receives a CSR that is already signed and never the
// key that signed it, so this is what lets PairIssuer produce a wider CSR for
// the same key.
type KeyRecorder struct {
	inner certmagic.KeyGenerator

	mu    sync.Mutex
	keys  map[string]crypto.Signer
	order []string
}

func NewKeyRecorder(inner certmagic.KeyGenerator) *KeyRecorder {
	return &KeyRecorder{inner: inner, keys: map[string]crypto.Signer{}}
}

func (r *KeyRecorder) GenerateKey() (crypto.PrivateKey, error) {
	key, err := r.inner.GenerateKey()
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("certpair: generated key of type %T cannot sign", key)
	}
	fingerprint, err := publicKeyFingerprint(signer.Public())
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, seen := r.keys[fingerprint]; !seen {
		r.order = append(r.order, fingerprint)
	}
	r.keys[fingerprint] = signer
	for len(r.order) > recorderCapacity {
		delete(r.keys, r.order[0])
		r.order = r.order[1:]
	}
	return key, nil
}

// Lookup finds the private key whose public half is pub.
func (r *KeyRecorder) Lookup(pub crypto.PublicKey) (crypto.Signer, bool) {
	fingerprint, err := publicKeyFingerprint(pub)
	if err != nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.keys[fingerprint]
	return key, ok
}

func publicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("certpair: marshalling public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
