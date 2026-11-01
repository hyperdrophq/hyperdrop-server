package certpair

import (
	"crypto"
	"testing"

	"github.com/caddyserver/certmagic"
)

func TestARecordedKeyIsFoundByItsPublicHalf(t *testing.T) {
	rec := NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256})
	key, err := rec.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("generated key is not a signer")
	}
	found, ok := rec.Lookup(signer.Public())
	if !ok {
		t.Fatal("the generated key was not recorded")
	}
	if found.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public()) == false {
		t.Fatal("Lookup returned a different key")
	}
}

func TestAnUnknownPublicKeyIsNotFound(t *testing.T) {
	rec := NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256})
	other, err := certmagic.StandardKeyGenerator{KeyType: certmagic.P256}.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := rec.Lookup(other.(crypto.Signer).Public()); ok {
		t.Fatal("a key this recorder never generated was found")
	}
}

// The recorder is consulted once per obtain or renew and must not grow without
// bound over the life of the process.
func TestTheRecorderKeepsOnlyTheMostRecentKeys(t *testing.T) {
	rec := NewKeyRecorder(certmagic.StandardKeyGenerator{KeyType: certmagic.P256})
	first, err := rec.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for i := 0; i < recorderCapacity; i++ {
		if _, err := rec.GenerateKey(); err != nil {
			t.Fatalf("generate: %v", err)
		}
	}
	if _, ok := rec.Lookup(first.(crypto.Signer).Public()); ok {
		t.Fatal("the oldest key was not evicted")
	}
	if got := rec.size(); got > recorderCapacity {
		t.Fatalf("recorder holds %d keys, capacity is %d", got, recorderCapacity)
	}
}

// size is how many keys the recorder holds.
func (r *KeyRecorder) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}
