package updatesig

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// A signature file is whatever was staged beside the binary. A file parse
// accepts has the five-line shape and names as signed exactly its first four
// lines, and no change to a file makes a binary verify that the release key
// did not sign under that statement.
func FuzzParse(f *testing.F) {
	f.Add([]byte(vectorFile))
	f.Add([]byte("hyperdrop-server-signature 3\nversion 1.0.0\narch amd64\nsha256 00\nsignature AA==\n"))
	f.Add([]byte("hyperdrop-server-signature 3\nversion 01.0.0\narch amd64 \n"))
	f.Add(bytes.Repeat([]byte("a\n"), MaxSize))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, sig []byte) {
		st, signed, signature, err := parse(sig)
		if err == nil {
			if parseVersion(st.Version) == nil || st.Arch == "" || len(st.SHA256) != 64 || len(signature) != ed25519.SignatureSize {
				t.Fatalf("accepted %q as %+v", sig, st)
			}
			if !bytes.HasPrefix(sig, signed) || bytes.Count(signed, []byte("\n")) != 4 {
				t.Fatalf("the signed bytes are not the file's first four lines: %q", signed)
			}
		}
		got, err := Verify([]string{vectorKey}, sig, bytes.NewReader(vectorRaw), "amd64", "0.9.0")
		if err == nil && (got.Version != "1.0.0" || !bytes.HasPrefix(sig, []byte(vectorFile[:len(vectorFile)-1]))) {
			t.Fatalf("a file the key did not sign verifies: %q", sig)
		}
	})
}
