package webapp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/fsatomic"
)

const testContract = "1.2.0"

// entry is one tar member of a test archive.
type entry struct {
	name string
	kind byte
	body string
	size int64 // a zero-filled body of this size when body is ""
	link string
}

// buildArchive packs files (name to contents) as a gzip tar, in name order.
func buildArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var es []entry
	for _, n := range names {
		es = append(es, entry{name: n, kind: tar.TypeReg, body: files[n]})
	}
	return buildEntries(t, es)
}

func buildEntries(t *testing.T, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Typeflag: e.kind, Mode: 0o644, Linkname: e.link, Format: tar.FormatPAX}
		var body []byte
		if e.kind == tar.TypeReg {
			body = []byte(e.body)
			if e.body == "" && e.size > 0 {
				body = make([]byte, e.size)
			}
			h.Size = int64(len(body))
		}
		if e.kind == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type signer struct {
	key ed25519.PrivateKey
	pub string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, pub: base64.StdEncoding.EncodeToString(pub)}
}

func (s signer) sign(t *testing.T, version string, build int, contract string, archive []byte) []byte {
	t.Helper()
	sig, err := webbundle.Sign(s.key, version, build, contract, archive)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func openStore(t *testing.T, dir string, s signer) *Store {
	t.Helper()
	st, err := Open(dir, []string{s.pub}, testContract)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func install(t *testing.T, st *Store, s signer, version string, build int, files map[string]string) {
	t.Helper()
	archive := buildArchive(t, files)
	if err := st.Install(archive, s.sign(t, version, build, testContract, archive), version, build, testContract); err != nil {
		t.Fatalf("install %s-%d: %v", version, build, err)
	}
}

func webDirs(t *testing.T, dataDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dataDir, "web"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

func TestInstallServesIndex(t *testing.T) {
	dir := t.TempDir()
	s := newSigner(t)
	st := openStore(t, dir, s)
	if _, ok := st.Current(); ok {
		t.Fatal("a new store has a current install")
	}
	install(t, st, s, "1.0.0", 3, map[string]string{"./index.html": "<p>hi</p>", "assets/app.js": "js"})
	inst, ok := st.Current()
	if !ok || inst.Version != "1.0.0" || inst.Build != 3 || inst.Contract != testContract {
		t.Fatalf("current = %+v %v", inst, ok)
	}
	if want := filepath.Join(dir, "web", "1.0.0-3"); inst.Dir != want {
		t.Fatalf("dir %s, want %s", inst.Dir, want)
	}
	got, err := os.ReadFile(filepath.Join(inst.Dir, "index.html"))
	if err != nil || string(got) != "<p>hi</p>" {
		t.Fatalf("index.html = %q, %v", got, err)
	}
	ptr, err := os.ReadFile(filepath.Join(dir, "web", "current"))
	if err != nil || string(ptr) != "1.0.0-3\n" {
		t.Fatalf("current pointer = %q, %v", ptr, err)
	}

	// A reopened store reads the same install back.
	again := openStore(t, dir, s)
	if inst2, ok := again.Current(); !ok || inst2 != inst {
		t.Fatalf("reopened current = %+v %v, want %+v", inst2, ok, inst)
	}
}

func TestInstallRefusesHostileArchives(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	index := entry{name: "index.html", kind: tar.TypeReg, body: "ok"}
	many := []entry{index}
	for i := range 2000 {
		many = append(many, entry{name: fmt.Sprintf("d%d", i), kind: tar.TypeDir})
	}
	big := []entry{index}
	for i := range 5 {
		big = append(big, entry{name: fmt.Sprintf("f%d.bin", i), kind: tar.TypeReg, size: 13 << 20})
	}
	cases := map[string]struct {
		entries  []entry
		contract string
		sigBy    *signer
		sigOver  []byte
		want     error
	}{
		"symlink":        {entries: []entry{index, {name: "evil", kind: tar.TypeSymlink, link: "/etc/passwd"}}, want: ErrBadArchive},
		"hardlink":       {entries: []entry{index, {name: "evil", kind: tar.TypeLink, link: "index.html"}}, want: ErrBadArchive},
		"dotdot":         {entries: []entry{index, {name: "../x", kind: tar.TypeReg, body: "x"}}, want: ErrBadArchive},
		"dotdot inside":  {entries: []entry{index, {name: "a/../../x", kind: tar.TypeReg, body: "x"}}, want: ErrBadArchive},
		"dotdot within":  {entries: []entry{index, {name: "a/../b.txt", kind: tar.TypeReg, body: "x"}}, want: ErrBadArchive},
		"absolute":       {entries: []entry{index, {name: "/abs", kind: tar.TypeReg, body: "x"}}, want: ErrBadArchive},
		"duplicate":      {entries: []entry{index, {name: "./index.html", kind: tar.TypeReg, body: "again"}}, want: ErrBadArchive},
		"reserved":       {entries: []entry{index, {name: metaName, kind: tar.TypeReg, body: "{}"}}, want: ErrBadArchive},
		"2001 entries":   {entries: many, want: ErrBadArchive},
		"65 MiB":         {entries: big, want: ErrBadArchive},
		"17 MiB file":    {entries: []entry{index, {name: "big.bin", kind: tar.TypeReg, size: 17 << 20}}, want: ErrBadArchive},
		"no index.html":  {entries: []entry{{name: "app.js", kind: tar.TypeReg, body: "x"}}, want: ErrBadArchive},
		"index is dir":   {entries: []entry{{name: "index.html/", kind: tar.TypeDir}}, want: ErrBadArchive},
		"other bytes":    {entries: []entry{index}, sigOver: []byte("other bytes"), want: webbundle.ErrUntrusted},
		"other key":      {entries: []entry{index}, sigBy: &other, want: webbundle.ErrUntrusted},
		"outside window": {entries: []entry{index}, contract: "1.3.0", want: ErrOutsideWindow},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			st := openStore(t, dir, s)
			install(t, st, s, "1.0.0", 1, map[string]string{"index.html": "old"})
			before, _ := st.Current()

			contract := c.contract
			if contract == "" {
				contract = testContract
			}
			archive := buildEntries(t, c.entries)
			by := s
			if c.sigBy != nil {
				by = *c.sigBy
			}
			over := archive
			if c.sigOver != nil {
				over = c.sigOver
			}
			sig := by.sign(t, "1.1.0", 1, contract, over)
			err := st.Install(archive, sig, "1.1.0", 1, contract)
			if !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			if after, ok := st.Current(); !ok || after != before {
				t.Fatalf("current moved to %+v %v", after, ok)
			}
			ptr, _ := os.ReadFile(filepath.Join(dir, "web", "current"))
			if string(ptr) != "1.0.0-1\n" {
				t.Fatalf("pointer %q", ptr)
			}
			for _, d := range webDirs(t, dir) {
				if strings.HasPrefix(d, ".staging-") || d == "1.1.0-1" {
					t.Fatalf("left %s behind", d)
				}
			}
		})
	}
}

func TestInstallAcceptsTheCapsExactly(t *testing.T) {
	s := newSigner(t)
	index := entry{name: "index.html", kind: tar.TypeReg, body: "ok"}
	atEntries := []entry{index}
	for i := range maxEntries - 1 {
		atEntries = append(atEntries, entry{name: fmt.Sprintf("d%d", i), kind: tar.TypeDir})
	}
	atTotal := []entry{index}
	for i := range 3 {
		atTotal = append(atTotal, entry{name: fmt.Sprintf("f%d.bin", i), kind: tar.TypeReg, size: maxFile})
	}
	atTotal = append(atTotal, entry{name: "rest.bin", kind: tar.TypeReg, size: maxTotal - 3*maxFile - 2})
	for name, es := range map[string][]entry{
		"2000 entries":    atEntries,
		"one 16 MiB file": {index, {name: "big.bin", kind: tar.TypeReg, size: maxFile}},
		"64 MiB in all":   atTotal,
	} {
		t.Run(name, func(t *testing.T) {
			st := openStore(t, t.TempDir(), s)
			archive := buildEntries(t, es)
			if err := st.Install(archive, s.sign(t, "1.0.0", 1, testContract, archive), "1.0.0", 1, testContract); err != nil {
				t.Fatalf("an archive exactly at the caps was refused: %v", err)
			}
			if _, ok := st.Current(); !ok {
				t.Fatal("not current")
			}
		})
	}
}

func TestInstallKeepsOnePrevious(t *testing.T) {
	dir := t.TempDir()
	s := newSigner(t)
	st := openStore(t, dir, s)
	install(t, st, s, "1.0.0", 1, map[string]string{"index.html": "a"})
	install(t, st, s, "1.0.1", 1, map[string]string{"index.html": "b"})
	install(t, st, s, "1.0.2", 1, map[string]string{"index.html": "c"})
	got := webDirs(t, dir)
	sort.Strings(got)
	if strings.Join(got, ",") != "1.0.1-1,1.0.2-1" {
		t.Fatalf("installs on disk %v, want the current and one previous", got)
	}
	if inst, _ := st.Current(); inst.Version != "1.0.2" {
		t.Fatalf("current %+v", inst)
	}

	// Installing the current bundle again changes nothing.
	install(t, st, s, "1.0.2", 1, map[string]string{"index.html": "c"})
	got = webDirs(t, dir)
	sort.Strings(got)
	if strings.Join(got, ",") != "1.0.1-1,1.0.2-1" {
		t.Fatalf("after a repeat install %v", got)
	}
}

func TestCrashBetweenExtractAndSwitchKeepsOld(t *testing.T) {
	dir := t.TempDir()
	s := newSigner(t)
	st := openStore(t, dir, s)
	install(t, st, s, "1.0.0", 1, map[string]string{"index.html": "old"})

	writePointer = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	t.Cleanup(func() { writePointer = fsatomic.Write })
	archive := buildArchive(t, map[string]string{"index.html": "new"})
	if err := st.Install(archive, s.sign(t, "1.1.0", 1, testContract, archive), "1.1.0", 1, testContract); err == nil {
		t.Fatal("an install whose pointer write failed succeeded")
	}
	if inst, _ := st.Current(); inst.Version != "1.0.0" {
		t.Fatalf("current moved to %+v", inst)
	}

	// A crash after the rename leaves the new directory beside an unchanged
	// pointer, and a half-extracted staging directory: the next boot serves
	// the old install and removes the staging directory.
	writePointer = fsatomic.Write
	if err := os.MkdirAll(filepath.Join(dir, "web", "1.1.0-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "web", ".staging-123", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	again := openStore(t, dir, s)
	inst, ok := again.Current()
	if !ok || inst.Version != "1.0.0" {
		t.Fatalf("reopened current %+v %v", inst, ok)
	}
	got, _ := os.ReadFile(filepath.Join(inst.Dir, "index.html"))
	if string(got) != "old" {
		t.Fatalf("serving %q", got)
	}
	for _, d := range webDirs(t, dir) {
		if strings.HasPrefix(d, ".staging-") {
			t.Fatalf("boot left %s", d)
		}
	}
}

func TestOpenIgnoresABrokenPointer(t *testing.T) {
	dir := t.TempDir()
	s := newSigner(t)
	if err := os.MkdirAll(filepath.Join(dir, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ptr := range []string{"../../etc\n", "1.0.0-1\n", ".staging-1\n", ""} {
		if err := os.WriteFile(filepath.Join(dir, "web", "current"), []byte(ptr), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := openStore(t, dir, s).Current(); ok {
			t.Fatalf("pointer %q gave a current install", ptr)
		}
	}
}

func TestUseDevDir(t *testing.T) {
	s := newSigner(t)
	st := openStore(t, t.TempDir(), s)
	dev := t.TempDir()
	st.UseDevDir(dev)
	inst, ok := st.Current()
	if !ok || inst.Dir != dev || inst.Contract != testContract {
		t.Fatalf("dev current %+v %v", inst, ok)
	}
}
