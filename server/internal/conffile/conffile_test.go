package conffile

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The package's conf_set rules: the first key line is replaced, later ones
// dropped, a missing one appended, and every other line kept as it was.
func TestSetTextMatchesThePackage(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "HYPERDROP_DOMAIN=a.example.com\n"},
		{"A=1\n", "A=1\nHYPERDROP_DOMAIN=a.example.com\n"},
		{"A=1", "A=1\nHYPERDROP_DOMAIN=a.example.com\n"},
		{"HYPERDROP_DOMAIN=old\nB= 2 \nHYPERDROP_DOMAIN=dup\n", "HYPERDROP_DOMAIN=a.example.com\nB= 2 \n"},
		{"# HYPERDROP_DOMAIN=x\nHYPERDROP_DOMAINS=y\n", "# HYPERDROP_DOMAIN=x\nHYPERDROP_DOMAINS=y\nHYPERDROP_DOMAIN=a.example.com\n"},
	} {
		if got := SetText(tc.in, "HYPERDROP_DOMAIN", "a.example.com"); got != tc.want {
			t.Errorf("SetText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The proxy list and the shared folder's name are written in double quotes,
// as conf_set writes them; every other value is bare.
func TestLineQuotesWhatConfSetQuotes(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{"HYPERDROP_TRUSTED_PROXIES", "127.0.0.1, ::1", `HYPERDROP_TRUSTED_PROXIES="127.0.0.1, ::1"`},
		{"HYPERDROP_TRUSTED_PROXIES", "", `HYPERDROP_TRUSTED_PROXIES=""`},
		{"HYPERDROP_SHARED_FOLDER", "Hyper Drop", `HYPERDROP_SHARED_FOLDER="Hyper Drop"`},
		{"HYPERDROP_HTTP_ADDR", ":5080", `HYPERDROP_HTTP_ADDR=:5080`},
		{"HYPERDROP_DOMAIN", "", `HYPERDROP_DOMAIN=`},
	} {
		if got := Line(tc.key, tc.value); got != tc.want {
			t.Errorf("Line(%q, %q) = %q, want %q", tc.key, tc.value, got, tc.want)
		}
	}
	if got := SetText("HYPERDROP_TRUSTED_PROXIES=\"\"\n", "HYPERDROP_TRUSTED_PROXIES", "10.0.0.1"); got != "HYPERDROP_TRUSTED_PROXIES=\"10.0.0.1\"\n" {
		t.Errorf("SetText = %q", got)
	}
}

func TestSetRewritesTheConfAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hyperdrop.conf")
	if err := os.WriteFile(path, []byte("HYPERDROP_HTTP_ADDR=:5080\nHYPERDROP_DATA_ID=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "HYPERDROP_HTTP_ADDR", ":8080"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "HYPERDROP_HTTP_ADDR=:8080\nHYPERDROP_DATA_ID=abc\n" {
		t.Fatalf("conf = %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %v, want the conf alone", entries)
	}
}

// A conf that is a link, a hard link, a directory or too large is never
// read, so it is never written either, and a link's target is untouched.
func TestReadRefusesAnythingButAPlainFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.conf")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir.conf")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(big, []byte(strings.Repeat("#\n", Limit)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, hard, sub, big, filepath.Join(dir, "missing.conf")} {
		if _, err := Read(p); err == nil {
			t.Errorf("Read(%s) succeeded", filepath.Base(p))
		}
		if err := Set(p, "A", "2"); err == nil {
			t.Errorf("Set(%s) succeeded", filepath.Base(p))
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "A=1\n" {
		t.Fatalf("target = %q", b)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link was replaced")
	}
}

// Write replaces a link planted at the path rather than writing through it.
func TestWriteReplacesALinkNeverFollowsIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "last-change.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, "new"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("target = %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("path is %v, %v", fi.Mode(), err)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	P := netip.MustParsePrefix
	cases := []struct {
		in   string
		want []netip.Prefix
	}{
		{"", nil},
		{"192.168.1.30", []netip.Prefix{P("192.168.1.30/32")}},
		{"10.0.0.0/8, 192.168.1.30", []netip.Prefix{P("10.0.0.0/8"), P("192.168.1.30/32")}},
		{"::ffff:192.168.1.30", []netip.Prefix{P("192.168.1.30/32")}},
		{"::ffff:10.0.0.0/104", []netip.Prefix{P("10.0.0.0/8")}},
		{" , 2001:db8::/32 ,", []netip.Prefix{P("2001:db8::/32")}},
		{"127.0.0.1, ::1", []netip.Prefix{P("127.0.0.1/32"), P("::1/128")}},
	}
	for _, c := range cases {
		got, err := ParseTrustedProxies(c.in)
		if err != nil {
			t.Fatalf("ParseTrustedProxies(%q): %v", c.in, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("ParseTrustedProxies(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"bogus", "10.0.0.0/8, bogus", "192.168.1.300", "10.0.0.0/33", "fe80::1%en0"} {
		_, err := ParseTrustedProxies(bad)
		if err == nil {
			t.Errorf("ParseTrustedProxies(%q) accepted a malformed entry", bad)
			continue
		}
		entry := strings.TrimSpace(bad[strings.LastIndex(bad, ",")+1:])
		if !strings.Contains(err.Error(), entry) {
			t.Errorf("ParseTrustedProxies(%q) error %q does not name %q", bad, err, entry)
		}
	}
	// A catch-all lets anyone forge an address, however it is spelled.
	for _, all := range []string{"0.0.0.0/0", "::/0", "::ffff:0:0/96", "10.0.0.0/8, 0.0.0.0/0"} {
		_, err := ParseTrustedProxies(all)
		entry := strings.TrimSpace(all[strings.LastIndex(all, ",")+1:])
		if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), "every address") {
			t.Errorf("ParseTrustedProxies(%q) = %v, want a refusal naming %q", all, err, entry)
		}
	}
}
