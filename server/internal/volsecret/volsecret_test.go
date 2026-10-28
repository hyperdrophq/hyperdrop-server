package volsecret

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var secret = bytes.Repeat([]byte{7}, 32)

func key(t *testing.T, s []byte, info string) Key {
	t.Helper()
	k, err := NewKey(s, info)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAValueOpensOnlyWithItsAssociatedData(t *testing.T) {
	k := key(t, secret, "use-a")
	sealed, err := k.Seal([]byte("plain"), []byte("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("plain")) {
		t.Fatal("the sealed value carries the plaintext")
	}
	if got, err := k.Open(sealed, []byte("alice")); err != nil || string(got) != "plain" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := k.Open(sealed, []byte("bob")); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("another row's associated data opened it: %v", err)
	}
}

// The label names one use: a value sealed for one never opens as another.
func TestAnotherLabelOrSecretCannotOpenIt(t *testing.T) {
	sealed, _ := key(t, secret, "use-a").Seal([]byte("plain"), []byte("alice"))
	if _, err := key(t, secret, "use-b").Open(sealed, []byte("alice")); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("another label opened it: %v", err)
	}
	if _, err := key(t, bytes.Repeat([]byte{8}, 32), "use-a").Open(sealed, []byte("alice")); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("another secret opened it: %v", err)
	}
}

func TestATamperedOrTruncatedValueIsUnreadable(t *testing.T) {
	k := key(t, secret, "use-a")
	sealed, _ := k.Seal([]byte("plain"), nil)
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 1
	for name, b := range map[string][]byte{"flipped": flipped, "short": sealed[:5], "empty": nil,
		"unknown version": append([]byte{9}, sealed[1:]...)} {
		if _, err := k.Open(b, nil); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	again, _ := k.Seal([]byte("plain"), nil)
	if bytes.Equal(sealed, again) {
		t.Fatal("two seals of one value are identical: the nonce is not random")
	}
}

// Only a missing secret is minted; one that is there is read back as is.
func TestLoadOrCreateMintsOnceAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil || len(a) != Len {
		t.Fatalf("first run: %d bytes, %v", len(a), err)
	}
	if fi, err := os.Stat(filepath.Join(dir, FileName)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the secret file: %v, %v", fi, err)
	}
	b, err := LoadOrCreate(dir)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("a second run minted another secret: %v", err)
	}
}

// An existing secret other accounts can read is made private when this
// process may change its mode, and the boot is refused when it may not,
// naming the file and its mode: a secret others can read opens every sealed
// value and signs every access cookie.
func TestLoadOrCreateRefusesOrTightensAReadableSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps no Unix mode bits")
	}
	dir := t.TempDir()
	minted, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreate(dir)
	if err != nil || !bytes.Equal(got, minted) {
		t.Fatalf("an owned 0644 secret: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the owned secret was left %v, %v; want 0600", fi.Mode().Perm(), err)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	saved := chmod
	chmod = func(string, fs.FileMode) error { return fs.ErrPermission }
	t.Cleanup(func() { chmod = saved })
	_, err = LoadOrCreate(dir)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "0640") {
		t.Fatalf("a 0640 secret this process cannot change: %v, want a refusal naming %s and 0640", err, path)
	}
}
