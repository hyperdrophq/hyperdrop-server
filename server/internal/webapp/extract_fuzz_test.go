package webapp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// An archive's bytes are whatever was staged. Whatever extract answers, the
// folder holds only regular files and directories within the caps, and an
// accepted archive has index.html at its root.
func FuzzExtract(f *testing.F) {
	index := entry{name: "index.html", kind: tar.TypeReg, body: "<!doctype html>"}
	for _, es := range [][]entry{
		{index, {name: "assets/", kind: tar.TypeDir}, {name: "assets/app.js", kind: tar.TypeReg, body: "x"}},
		{index, {name: "evil", kind: tar.TypeSymlink, link: "/etc/passwd"}},
		{index, {name: "a/../../x", kind: tar.TypeReg, body: "x"}},
		{index, {name: "INDEX.HTML", kind: tar.TypeReg, body: "again"}},
		{index, {name: metaName, kind: tar.TypeReg, body: "{}"}},
		{{name: "index.html/", kind: tar.TypeDir}},
	} {
		gz := buildEntries(f, es)
		f.Add(gz, true)
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			f.Fatal(err)
		}
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(zr); err != nil {
			f.Fatal(err)
		}
		f.Add(raw.Bytes(), false)
	}
	f.Add([]byte{0x1f, 0x8b}, true)

	// compressed false wraps data in gzip first, so the fuzzer mutates the
	// tar stream itself rather than a deflate stream.
	f.Fuzz(func(t *testing.T, data []byte, compressed bool) {
		archive := data
		if !compressed {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			zw.Write(data)
			zw.Close()
			archive = buf.Bytes()
		}
		dir := t.TempDir()
		err := extract(archive, dir)

		var files int
		var total int64
		walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == dir {
				return nil
			}
			files++
			info, err := d.Info()
			if err != nil {
				return err
			}
			switch {
			case info.Mode().IsDir():
			case info.Mode().IsRegular():
				if info.Size() > maxFile {
					t.Fatalf("%s holds %d bytes", p, info.Size())
				}
				total += info.Size()
			default:
				t.Fatalf("%s is neither a file nor a directory: %v", p, info.Mode())
			}
			if d.Name() == metaName && filepath.Dir(p) == dir {
				t.Fatalf("the archive wrote %s", metaName)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
		if total > maxTotal {
			t.Fatalf("%d bytes unpacked", total)
		}
		if err != nil {
			return
		}
		if files > maxEntries {
			t.Fatalf("%d entries accepted", files)
		}
		info, statErr := os.Lstat(filepath.Join(dir, "index.html"))
		if statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("accepted without a regular index.html: %v", statErr)
		}
	})
}

// A member's name either stays inside the bundle or is refused.
func FuzzMemberName(f *testing.F) {
	for _, s := range []string{"index.html", "./a/b.js", "a/../b", "/abs", "a\\b", "", ".", "a//b", "a/./b", "..", "a/\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		name, ok := memberName(raw)
		if !ok {
			return
		}
		if name != "." && (!fs.ValidPath(name) || !filepath.IsLocal(filepath.FromSlash(name))) {
			t.Fatalf("memberName(%q) = %q", raw, name)
		}
	})
}
