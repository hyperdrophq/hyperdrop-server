package pushseal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"testing"
	"unicode/utf8"
)

func fuzzKey(f *testing.F) *ecdh.PrivateKey {
	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		f.Fatal(err)
	}
	return priv
}

// Anyone who knows a phone's public key can seal to it, so the plaintext of a
// push is whatever its sender wrote. Open answers only a v1 message with a
// kind, and anything else, sealed or not, is refused with nothing read.
func FuzzOpen(f *testing.F) {
	priv := fuzzKey(f)
	pk, err := suite.kem.NewPublicKey(priv.PublicKey().Bytes())
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"v":1,"kind":"inboxReceived","title":"t","body":"b","unseen":2}`), true)
	f.Add([]byte(`{}`), true)
	f.Add([]byte(`null`), true)
	f.Add([]byte(`{"v":2,"kind":"domain"}`), true)
	f.Add([]byte(`{"v":1,"kind":""}`), true)
	f.Add([]byte(`{"v":1,"kind":"x","unseen":"many"}`), true)
	f.Add([]byte("not base64 at all"), false)
	f.Add([]byte{}, false)
	// sealed true seals data to the phone's key first, so the fuzzer reaches
	// the message reader; false hands data to Open as the ciphertext itself.
	f.Fuzz(func(t *testing.T, data []byte, sealed bool) {
		ciphertext := string(data)
		if sealed {
			ct, err := hpke.Seal(pk, suite.kdf, suite.aead, []byte(Info), data)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext = base64.StdEncoding.EncodeToString(ct)
		}
		m, err := Open(priv, ciphertext)
		if err != nil {
			if m != (Message{}) {
				t.Fatalf("a refused push answered %+v", m)
			}
			return
		}
		if !sealed {
			t.Fatalf("opened %q, which nobody sealed", data)
		}
		if m.V != 1 || m.Kind == "" {
			t.Fatalf("opened %q as %+v", data, m)
		}
		var again Message
		if json.Unmarshal(data, &again) != nil || again != m {
			t.Fatalf("opened %q as %+v, its JSON reads %+v", data, m, again)
		}
	})
}

// A notification's text is a share's name or a sender's file name. Seal fits
// any message under the size a push carries, keeps its routing fields whole
// and never cuts a character in two.
func FuzzSeal(f *testing.F) {
	priv := fuzzKey(f)
	pub := priv.PublicKey().Bytes()
	f.Add("Photos", "Anna sent 3 files", "inbox-1", "tag", "ref", 3)
	f.Add(string(bytes.Repeat([]byte("é"), 4000)), string(bytes.Repeat([]byte("\x00\"<"), 3000)), "t", "g", "r", 0)
	f.Add("\xff\xfe", "", "", "", "", -1)
	f.Fuzz(func(t *testing.T, title, body, thread, tag, ref string, unseen int) {
		in := Message{V: 1, Kind: "inboxReceived", Title: title, Body: body, Thread: thread, Tag: tag, Ref: ref, Unseen: unseen}
		ct, err := Seal(pub, in)
		if err != nil {
			return
		}
		if len(ct) > MaxCiphertext {
			t.Fatalf("a sealed message is %d bytes, more than %d", len(ct), MaxCiphertext)
		}
		out, err := Open(priv, ct)
		if err != nil {
			t.Fatalf("a sealed message does not open: %v", err)
		}
		// JSON carries text, so bytes that are not UTF-8 come back replaced.
		text := func(s string) string {
			b, _ := json.Marshal(s)
			var v string
			json.Unmarshal(b, &v)
			return v
		}
		if out.Kind != in.Kind || out.Unseen != in.Unseen || out.Thread != text(thread) || out.Tag != text(tag) || out.Ref != text(ref) {
			t.Fatalf("the routing fields changed: sent %+v, opened %+v", in, out)
		}
		if !utf8.ValidString(out.Title) || !utf8.ValidString(out.Body) {
			t.Fatalf("a cut left half a character: %q / %q", out.Title, out.Body)
		}
	})
}
