package sharefs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Secret is the per-server HMAC key that signs public-access cookies. A
// copy, so no caller can change the key under the others.
func (f *FS) Secret() []byte {
	return append([]byte(nil), f.secret...)
}

// ServerID is a stable, non-secret identifier for this install, derived
// from the per-volume secret: the same data volume gives the same id across
// restarts and address changes, a fresh volume a new one. A one-way,
// domain-separated HMAC of the secret, so publishing it never weakens the
// cookie key. Clients bind a registry entry to it to detect a swapped box.
func (f *FS) ServerID() string {
	mac := hmac.New(sha256.New, f.Secret())
	mac.Write([]byte("hyperdrop-server-id-v1"))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}
