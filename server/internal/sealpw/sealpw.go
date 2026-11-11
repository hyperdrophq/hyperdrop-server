// Package sealpw keeps a share's password readable by its owner on every
// device. The server stores, beside the bcrypt hash the public form checks,
// the password sealed with AES-256-GCM under a key derived (HKDF-SHA256) from
// the volume's secret (<data>/secret, volsecret), with the share id as
// associated data so a sealed copy cannot be moved onto another share.
//
// The bcrypt hash stored beside the copy is part of the associated data. An
// older server that changes the password rewrites the hash and not the copy,
// so a copy opens only while the password it holds is the share's password:
// the copy is an addition the previous release ignores, and it stays correct
// when that release has written the row since.
//
// The password gates files this same server stores as plain files, so
// whoever can read the sealed copy and the secret can read what it protects
// directly; the copy adds no access, only the convenience of reading back
// what was set.
package sealpw

import (
	"errors"

	"hyperdrop/server/internal/volsecret"
)

// info separates this key from every other use of the volume secret.
const info = "hyperdrop-share-password-v1"

// ErrUnreadable: the copy does not open under this secret for this share
// and hash (another volume's secret, another share, a changed password,
// damage). Callers read it as "no readable copy", never as a failure of the
// request.
var ErrUnreadable = errors.New("sealpw: the sealed password does not open")

// associated binds a copy to its share and to the hash stored beside it. A
// share id never holds a NUL, so the separator keeps the two fields apart.
func associated(shareID, hash string) []byte {
	return []byte(shareID + "\x00" + hash)
}

// Seal answers format || nonce || ciphertext for password, or nil when
// there is no password or no hash to bind it to.
func Seal(secret []byte, shareID, hash, password string) ([]byte, error) {
	if password == "" || hash == "" {
		return nil, nil
	}
	k, err := volsecret.NewKey(secret, info)
	if err != nil {
		return nil, err
	}
	return k.Seal([]byte(password), associated(shareID, hash))
}

// Open answers the password sealed for shareID beside hash, or ErrUnreadable.
func Open(secret []byte, shareID, hash string, sealed []byte) (string, error) {
	k, err := volsecret.NewKey(secret, info)
	if err != nil {
		return "", err
	}
	if hash == "" {
		return "", ErrUnreadable
	}
	plain, err := k.Open(sealed, associated(shareID, hash))
	if err != nil {
		return "", ErrUnreadable
	}
	return string(plain), nil
}
