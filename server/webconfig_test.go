package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/webapp"
)

func lookupIn(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func devKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func TestDevDirNeedsAllowPrivate(t *testing.T) {
	dir := t.TempDir()
	key := devKey(t)
	for _, env := range []map[string]string{
		{"HYPERDROP_WEB_DEV_DIR": dir},
		{"HYPERDROP_WEB_DEV_KEYS": key},
	} {
		_, err := resolveWeb(lookupIn(env), false)
		if err == nil || !strings.Contains(err.Error(), "HYPERDROP_ALLOW_PRIVATE=1") {
			t.Errorf("%v without HYPERDROP_ALLOW_PRIVATE: %v", env, err)
		}
	}

	other := devKey(t)
	wc, err := resolveWeb(lookupIn(map[string]string{
		"HYPERDROP_WEB_DEV_DIR": dir, "HYPERDROP_WEB_DEV_KEYS": key + ", " + other,
	}), true)
	if err != nil {
		t.Fatal(err)
	}
	if wc.DevDir != dir {
		t.Fatalf("DevDir = %q", wc.DevDir)
	}
	if want := append(slices.Clone(webbundle.TrustedKeys), key, other); !slices.Equal(wc.Keys, want) {
		t.Fatalf("Keys = %v, want %v", wc.Keys, want)
	}

	// The variable the server reads is the one webbundle names.
	if webbundle.DevKeysEnv != "HYPERDROP_WEB_DEV_KEYS" {
		t.Fatalf("webbundle.DevKeysEnv = %q", webbundle.DevKeysEnv)
	}
}

func TestResolveWebRefusesBadDevOptions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "index.html")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	for _, env := range []map[string]string{
		{"HYPERDROP_WEB_DEV_DIR": file},
		{"HYPERDROP_WEB_DEV_DIR": filepath.Join(t.TempDir(), "missing")},
		{"HYPERDROP_WEB_DEV_DIR": "relative/dir"},
		{"HYPERDROP_WEB_DEV_KEYS": "not base64!"},
		{"HYPERDROP_WEB_DEV_KEYS": short},
		{"HYPERDROP_WEB_DEV_KEYS": devKey(t) + ",,"},
	} {
		if _, err := resolveWeb(lookupIn(env), true); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
}

func TestResolveWebKeepsTheReleaseKeysAlone(t *testing.T) {
	wc, err := resolveWeb(lookupIn(nil), false)
	if err != nil {
		t.Fatal(err)
	}
	if wc.DevDir != "" || !slices.Equal(wc.Keys, webbundle.TrustedKeys) {
		t.Fatalf("no development options: %+v", wc)
	}
	if wc.Base != webapp.DefaultBase || wc.BaseErr != nil {
		t.Fatalf("Base = %q %v", wc.Base, wc.BaseErr)
	}
	// An empty server manifest directory turns the web fetch off too.
	if wc, _ := resolveWeb(lookupIn(map[string]string{"HYPERDROP_SERVER_RELEASES": ""}), false); wc.Base != "" || wc.BaseErr != nil {
		t.Fatalf("HYPERDROP_SERVER_RELEASES empty: %q %v", wc.Base, wc.BaseErr)
	}
	// A malformed directory turns it off with the reason, without refusing
	// to boot.
	wc, err = resolveWeb(lookupIn(map[string]string{"HYPERDROP_WEB_RELEASES": "ftp://x/"}), false)
	if err != nil || wc.Base != "" || wc.BaseErr == nil {
		t.Fatalf("a malformed HYPERDROP_WEB_RELEASES: %q %v %v", wc.Base, wc.BaseErr, err)
	}
}
