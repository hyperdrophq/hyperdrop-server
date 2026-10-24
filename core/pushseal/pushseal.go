// Package pushseal is what a push carries and how it is sealed so only one
// phone can read it, and how that phone opens it: HPKE (RFC 9180) with
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 to the public
// key that phone made. The relay and Apple see only the ciphertext.
package pushseal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// Info binds every seal to this protocol and version; the phone opens with
// the same bytes.
const Info = "HyperDrop push v1"

const (
	// MaxCiphertext is the longest sealed message, in base64 characters. The
	// relay refuses a ciphertext whose APNs payload would pass 4 KB, which
	// leaves 3,976 characters beside its envelope; this leaves room for that
	// envelope to grow.
	MaxCiphertext = 3800
	// MaxPlaintext is the JSON that seals to at most MaxCiphertext: 32 bytes
	// of encapsulated key and 16 of tag ride on top, and base64 adds a third.
	MaxPlaintext = 2800
)

// Message is one notification, as the phone's Notification Service
// Extension shows it.
type Message struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"` // inboxReceived | accessRevoked | domain | serverUpdate
	Title  string `json:"title"`
	Body   string `json:"body"`
	Thread string `json:"thread"`        // groups the notifications of one inbox
	Tag    string `json:"tag"`           // the registration's tag: which account on the phone
	Unseen int    `json:"unseen"`        // the account's unseen inbox files now
	Ref    string `json:"ref,omitempty"` // the inbox or share a tap opens
}

var suite = struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()}

// ParsePublicKey reports whether raw is a public key a seal can use.
func ParsePublicKey(raw []byte) error {
	if len(raw) != 32 {
		return errors.New("pushseal: an X25519 public key is 32 bytes")
	}
	pk, err := suite.kem.NewPublicKey(raw)
	if err != nil {
		return err
	}
	// A low-order point parses but cannot agree on a secret: try one seal.
	_, err = hpke.Seal(pk, suite.kdf, suite.aead, []byte(Info), []byte("{}"))
	return err
}

// Seal fits m under MaxPlaintext and seals it to publicKey.
func Seal(publicKey []byte, m Message) (string, error) {
	pk, err := suite.kem.NewPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	plain, err := fit(m)
	if err != nil {
		return "", err
	}
	sealed, err := hpke.Seal(pk, suite.kdf, suite.aead, []byte(Info), plain)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open is the phone's side: the Android core opens with it, and tests and
// the iOS fixture use it (the iPhone opens with CryptoKit). It refuses a
// plaintext that is not a v1 message with a kind, as the iPhone's opener does,
// so a sealed `{}` or `null` never reads as an empty notification.
func Open(priv *ecdh.PrivateKey, ciphertext string) (Message, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		return Message{}, err
	}
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return Message{}, err
	}
	plain, err := hpke.Open(k, suite.kdf, suite.aead, []byte(Info), raw)
	if err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(plain, &m); err != nil {
		return Message{}, err
	}
	if m.V != 1 || m.Kind == "" {
		return Message{}, errors.New("pushseal: not a v1 push message")
	}
	return m, nil
}

// fit marshals m, cutting the body and then the title until it fits. The
// routing fields (kind, thread, tag, ref) are never cut: they are short and
// the phone needs them whole.
func fit(m Message) ([]byte, error) {
	for {
		b, err := json.Marshal(m)
		if err != nil || len(b) <= MaxPlaintext {
			return b, err
		}
		over := len(b) - MaxPlaintext
		switch {
		case m.Body != "" && m.Body != "…":
			m.Body = cut(m.Body, over)
		case m.Title != "" && m.Title != "…":
			m.Title = cut(m.Title, over)
		default:
			return nil, errors.New("pushseal: the message does not fit even with its text cut")
		}
	}
}

// cut drops at least n bytes (JSON escaping can make the marshalled cost of
// a rune larger than its UTF-8 length, so the loop in fit may cut again)
// and ends the text with an ellipsis, never splitting a rune.
func cut(s string, n int) string {
	keep := len(s) - n - len("…")
	if keep <= 0 {
		return "…"
	}
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return s[:keep] + "…"
}
