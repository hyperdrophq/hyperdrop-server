// Package volsecret owns the volume secret, <data>/secret, and the sealing
// keys derived from it.
//
// The secret is a file beside the database, never a row in it, so neither
// the database nor a backup of it (VACUUM INTO, under <data>/backups/) holds
// it: a copy of the database alone opens no sealed value.
//
// A Key is AES-256-GCM under a key derived from the secret with HKDF-SHA256
// and a label naming its one use (Subkey), so a value sealed for one use
// never opens as another. Every sealed value is format || nonce || ciphertext, and its
// associated data binds it to the row it belongs to.
package volsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"hyperdrop/server/internal/fsatomic"
)

// FileName is the secret's name inside the data directory.
const FileName = "secret"

// Len is the size LoadOrCreate mints and the least it accepts.
const Len = 32

// chmod is os.Chmod; a test stands in a refusal for a file another account
// owns.
var chmod = os.Chmod

// LoadOrCreate reads <dataDir>/secret, creating a 32-byte random one on
// first run. Only a missing file is a first run: the secret is the server's
// identity (sharefs ServerID), every access cookie's key and every sealed
// value's, so a file that is there but unreadable (a restore with the wrong
// owner, a disk error) or too short refuses the boot rather than being
// replaced, which would make every client refuse the server as a different
// one and leave every sealed value unopenable. A secret other accounts may
// read (privateFile) is made 0600, or refuses the boot when this process
// cannot change its mode.
func LoadOrCreate(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, FileName)
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) >= Len:
		if err := privateFile(path); err != nil {
			return nil, err
		}
		return b, nil
	case err == nil:
		return nil, fmt.Errorf("%s holds %d bytes, not a %d-byte secret: restore it from a backup of this volume, or remove it to mint a new one, which every client will refuse as a different server", path, len(b), Len)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("reading the volume secret: %w", err)
	}
	b = make([]byte, Len)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := fsatomic.Write(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// privateFile makes the file at path readable by its owner alone when any
// group or other bit is set, and refuses when this process may not change
// its mode (another account owns it): a secret others can read opens every
// sealed value and signs every access cookie. Windows keeps no Unix mode
// bits, so there is nothing to judge.
func privateFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading the volume secret: %w", err)
	}
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	if err := chmod(path, 0o600); err != nil {
		return fmt.Errorf("%s is readable by other accounts (mode %#o) and this process cannot make it private (%v): run chmod 600 on it as its owner, or chown it to the account the server runs as", path, perm, err)
	}
	return nil
}

// format leads every sealed value, so a later scheme can be told apart.
const format byte = 1

// ErrUnreadable: the value does not open under this key with this
// associated data (another volume's secret, another row, damage).
var ErrUnreadable = errors.New("volsecret: the sealed value does not open")

// Key seals and opens values for one use of the volume secret.
type Key struct{ g cipher.AEAD }

// Subkey derives the 32-byte key for the use info names from secret, with
// HKDF-SHA256 and info as its label: the derivation NewKey seals under, for
// a use that needs the key itself (an HMAC).
func Subkey(secret []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, 32)
}

// NewKey derives the key for the use info names from secret.
func NewKey(secret []byte, info string) (Key, error) {
	key, err := Subkey(secret, info)
	if err != nil {
		return Key{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Key{}, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return Key{}, err
	}
	return Key{g}, nil
}

// Seal answers format || nonce || ciphertext for plain, bound to ad.
func (k Key) Seal(plain, ad []byte) ([]byte, error) {
	nonce := make([]byte, k.g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{format}, nonce...)
	return k.g.Seal(out, nonce, plain, ad), nil
}

// Open answers what Seal sealed with the same ad, or ErrUnreadable.
func (k Key) Open(sealed, ad []byte) ([]byte, error) {
	n := k.g.NonceSize()
	if len(sealed) < 1+n+k.g.Overhead() || sealed[0] != format {
		return nil, ErrUnreadable
	}
	plain, err := k.g.Open(nil, sealed[1:1+n], sealed[1+n:], ad)
	if err != nil {
		return nil, ErrUnreadable
	}
	return plain, nil
}
