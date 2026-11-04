package sharefs

import (
	"os"
	"path/filepath"
	"testing"
)

// serverIDVector is the fixed derivation vector every client that has stored
// a server id relies on: the id for the secret whose bytes are 1 through 32
// (byte(i+1)).
const serverIDVector = "9fd50944021c8ecb"

func TestServerIDIsAStableHMACOfTheSecret(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, secretFileName), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.ServerID(); got != serverIDVector {
		t.Fatalf("ServerID = %q, want %q (the derivation is a published contract)", got, serverIDVector)
	}
	g, err := Open(dir)
	if err != nil || g.ServerID() != serverIDVector {
		t.Fatalf("a reopen keeps the id: %q, %v", g.ServerID(), err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, secretFileName), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, err := Open(other); err != nil || h.ServerID() == serverIDVector {
		t.Fatalf("another secret, another id: %v", err)
	}
}

// Only a missing secret is a first run. One that is there but unreadable or
// too short refuses the open, because replacing it would change the server's
// identity under every client.
func TestASecretThatCannotBeReadRefusesTheOpen(t *testing.T) {
	dir := t.TempDir()
	f, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := f.ServerID()
	path := filepath.Join(dir, secretFileName)
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a short secret was accepted")
	}
	if data, _ := os.ReadFile(path); string(data) != "short" {
		t.Fatal("the short secret was replaced")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // reads fail with EISDIR
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("an unreadable secret was accepted")
	}
	os.Remove(path)
	g, err := Open(dir)
	if err != nil || g.ServerID() == id {
		t.Fatalf("a missing secret mints a fresh one: %v", err)
	}
}
