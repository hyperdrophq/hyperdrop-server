package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
)

// sourceConf reads the conf the way the package's start script does.
func sourceConf(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", `. "$1"; echo "$HYPERDROP_DOMAIN|$HYPERDROP_DDNS_NAME"`, "sh", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sourcing the conf: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// otherLines is every line of a conf but its two address lines.
func otherLines(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, "HYPERDROP_DOMAIN=") && !strings.HasPrefix(l, "HYPERDROP_DDNS_NAME=") {
			out = append(out, l)
		}
	}
	return out
}

func TestTheConfFollowsTheCurrentAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hyperdrop.conf")
	const before = "HYPERDROP_DDNS_NAME=bobby\n" +
		"HYPERDROP_HTTP_ADDR=:5080\n" +
		"HYPERDROP_HTTPS_ADDR=:5443\n" +
		"HYPERDROP_TRUSTED_PROXIES=\"127.0.0.1 10.20.30.40\"\n" +
		"HYPERDROP_DATA_ID=0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sourceConf(t, path); got != "|bobby" {
		t.Fatalf("before: %q", got)
	}
	dom, err := domain.Load(filepath.Join(dir, "domain"), "")
	if err != nil {
		t.Fatal(err)
	}
	dom.BehindNAT = true
	dom.Changed = (&confAddress{path: path}).Sync

	if err := dom.Adopt("share.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := sourceConf(t, path); got != "share.example.com|" {
		t.Fatalf("after an own domain: %q", got)
	}
	after, _ := os.ReadFile(path)
	if a, b := otherLines(string(after)), otherLines(before); strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("other lines changed:\n%q\nwant\n%q", a, b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}

	if err := dom.Adopt("carol.hyperdrop.link"); err != nil {
		t.Fatal(err)
	}
	if got := sourceConf(t, path); got != "|carol" {
		t.Fatalf("after a free name: %q", got)
	}
	after, _ = os.ReadFile(path)
	if a, b := otherLines(string(after)), otherLines(before); strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("other lines changed:\n%q\nwant\n%q", a, b)
	}
	if n := strings.Count(string(after), "HYPERDROP_DOMAIN="); n != 1 {
		t.Fatalf("%d HYPERDROP_DOMAIN lines", n)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".hyperdrop.conf-") {
			t.Fatalf("left %s behind", e.Name())
		}
	}
}

// The conf is edited only when it is a plain file: a link is left alone and
// its target untouched.
func TestTheConfIsNotEditedThroughALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("HYPERDROP_DDNS_NAME=bobby\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "hyperdrop.conf")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeConfAddress(path, "share.example.com"); err == nil {
		t.Fatal("a linked conf was written")
	}
	if b, _ := os.ReadFile(target); string(b) != "HYPERDROP_DDNS_NAME=bobby\n" {
		t.Fatalf("target = %q", b)
	}
	if fi, _ := os.Lstat(path); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link was replaced")
	}
}

func TestNoConfIsANoOp(t *testing.T) {
	(&confAddress{}).Sync("share.example.com")
	var c *confAddress
	c.Sync("share.example.com")
	dir := t.TempDir()
	path := filepath.Join(dir, "hyperdrop.conf")
	if err := os.WriteFile(path, []byte("HYPERDROP_DOMAIN=share.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	(&confAddress{path: path}).Sync("")
	if b, _ := os.ReadFile(path); string(b) != "HYPERDROP_DOMAIN=share.example.com\n" {
		t.Fatalf("an empty address rewrote the conf: %q", b)
	}
}
