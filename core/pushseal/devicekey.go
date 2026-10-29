package pushseal

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
)

// NewDeviceKey makes the X25519 keypair a phone registers with: the private
// half, kept in the device's secret store, and the public half the server
// seals to. Both are the raw 32 bytes.
func NewDeviceKey() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// PublicKeyOf answers the public half of a raw private key.
func PublicKeyOf(priv []byte) ([]byte, error) {
	k, err := privateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// OpenRaw is Open for a raw private key.
func OpenRaw(priv []byte, ciphertext string) (Message, error) {
	k, err := privateKey(priv)
	if err != nil {
		return Message{}, err
	}
	return Open(k, ciphertext)
}

func privateKey(priv []byte) (*ecdh.PrivateKey, error) {
	if len(priv) != 32 {
		return nil, errors.New("pushseal: an X25519 private key is 32 bytes")
	}
	return ecdh.X25519().NewPrivateKey(priv)
}
