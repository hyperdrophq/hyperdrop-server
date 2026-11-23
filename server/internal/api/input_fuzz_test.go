package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"hyperdrop/server/internal/shareid"
)

// A batch's tar stream is whatever an account sent. Every entry the reader
// admits is a regular file within the caps, every failure is a 4xx refusal,
// and the meter never reads past its bound.
func FuzzBatchReader(f *testing.F) {
	f.Add(tarOf(f, map[string]string{"a.txt": "one", "dir/b.txt": "two"}, []string{"a.txt", "dir/b.txt"}))
	f.Add(tarOf(f, map[string]string{"a.txt": "one"}, []string{"a.txt"})[:600])
	var odd bytes.Buffer
	tw := tar.NewWriter(&odd)
	tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	f.Add(odd.Bytes())
	var long bytes.Buffer
	tw = tar.NewWriter(&long)
	tw.WriteHeader(&tar.Header{Name: string(bytes.Repeat([]byte("n/"), 200)) + "x", Typeflag: tar.TypeReg, Size: 1,
		PAXRecords: map[string]string{"HYPERDROP.note": "v"}})
	tw.Write([]byte("x"))
	tw.Close()
	f.Add(long.Bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		meter := newTarMeter(bytes.NewReader(data))
		tr := tar.NewReader(meter)
		batch := batchReader{tr: tr, meter: meter}
		files, total := 0, int64(0)
		for {
			hdr, err := batch.next(relPath, files, total)
			if err != nil {
				var r *refusal
				if !errors.As(err, &r) || r.status < 400 || r.status > 499 {
					t.Fatalf("a failure that is not a 4xx refusal: %v", err)
				}
				break
			}
			if hdr == nil {
				break
			}
			if hdr.Typeflag != tar.TypeReg {
				t.Fatalf("admitted an entry of type %q: %q", hdr.Typeflag, hdr.Name)
			}
			if hdr.Size < 0 || total+hdr.Size > batchMaxBytes {
				t.Fatalf("admitted %d bytes after %d", hdr.Size, total)
			}
			if tooDeep(hdr.Name) {
				t.Fatalf("admitted a path past the depth cap: %q", hdr.Name)
			}
			if hdr.Name != relPath(hdr.Name) {
				t.Fatalf("admitted a name that is not NFC: %q", hdr.Name)
			}
			files++
			total += hdr.Size
			// A sparse entry reads as zeros no input byte pays for, so the
			// drain is bounded; the next Next() skips the rest.
			if _, err := io.CopyN(io.Discard, tarBody{tr}, 1<<20); err != nil && err != io.EOF {
				var r *refusal
				if !errors.As(err, &r) {
					t.Fatalf("an entry's read failed without a refusal: %v", err)
				}
				break
			}
		}
		if batch.entries > batchMaxEntries+1 || files > batchMaxFiles {
			t.Fatalf("%d entries, %d files", batch.entries, files)
		}
		if meter.read > int64(len(data)) || meter.read > meter.limit {
			t.Fatalf("the meter read %d of %d bytes (limit %d)", meter.read, len(data), meter.limit)
		}
	})
}

// A range header is the client's text: an accepted upload range lies inside
// the file and is never empty except for the empty file's, and a served range
// never leaves the file.
func FuzzRanges(f *testing.F) {
	f.Add("0-5", "bytes=0-4", int64(5))
	f.Add("0-0", "bytes=-1", int64(0))
	f.Add("+1-5", "bytes=2-", int64(10))
	f.Add("9223372036854775807-9223372036854775808", "bytes=-9223372036854775807", int64(1<<62))
	f.Add("5-3", "bytes=0-1,3-4", int64(8))
	f.Fuzz(func(t *testing.T, upload, serve string, size int64) {
		if size < 0 {
			size = 0
		}
		if rg, err := parseUploadRange(upload, size); err == nil {
			empty := rg.Start == 0 && rg.End == 0 && size == 0
			if !empty && (rg.Start < 0 || rg.Start >= rg.End || rg.End > size) {
				t.Fatalf("parseUploadRange(%q, %d) = %+v", upload, size, rg)
			}
		}
		start, end, partial, ok := parseLiveShareRange(serve, size)
		if partial && !ok {
			t.Fatalf("parseLiveShareRange(%q, %d): partial without ok", serve, size)
		}
		if partial && (start < 0 || start > end || end >= size) {
			t.Fatalf("parseLiveShareRange(%q, %d) = %d-%d", serve, size, start, end)
		}
		if !partial && (start != 0 || end != size-1) {
			t.Fatalf("parseLiveShareRange(%q, %d) = %d-%d for the whole file", serve, size, start, end)
		}
	})
}

// A request body's encoding is the client's. Whatever a zstd body holds, a
// failed read is a 4xx refusal, and the decoder goes back to its pool.
func FuzzDecodeBody(f *testing.F) {
	enc, _ := zstd.NewWriter(nil)
	f.Add(enc.EncodeAll([]byte("hello, batch"), nil))
	f.Add(enc.EncodeAll(bytes.Repeat([]byte{0}, 1<<20), nil))
	f.Add(enc.EncodeAll([]byte("cut short"), nil)[:12])
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(data))
		r.Header.Set("Content-Encoding", "zstd")
		w := httptest.NewRecorder()
		body, cleanup, decoded, err := decodeBody(w, r)
		if err != nil {
			if w.Code < 400 || w.Code > 499 {
				t.Fatalf("a refused body answered %d", w.Code)
			}
			return
		}
		defer cleanup()
		if !decoded {
			t.Fatal("a zstd body was not decoded")
		}
		// The bound keeps a small frame that unpacks to gigabytes from
		// stalling the run; the routes bound what they read themselves.
		if _, err := io.Copy(io.Discard, io.LimitReader(body, 64<<20)); err != nil {
			var ref *refusal
			if !errors.As(err, &ref) || ref.status < 400 || ref.status > 499 {
				t.Fatalf("a failed read is not a 4xx refusal: %v", err)
			}
		}
	})
}

// A JSON body is the client's text. One the strict decoder accepts holds one
// value and no field the server does not speak, so it decodes the same way
// again from its own encoding.
func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"name":"a","password":"correct horse","files":[{"path":"a/b.txt","size":3}]}`))
	f.Add([]byte(`{"name":"a"} {"name":"b"}`))
	f.Add([]byte(`{"nope":1}`))
	f.Add([]byte(`{"files":[{"path":"a","size":-1}],"expiresInSeconds":9223372036854775807}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var req createShareRequest
		if decodeRequest(data, &req) != nil {
			return
		}
		again, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("an accepted body does not encode: %v", err)
		}
		var second createShareRequest
		if err := decodeRequest(again, &second); err != nil {
			t.Fatalf("an accepted body's own encoding is refused: %v\n%s", err, again)
		}
		if !reflect.DeepEqual(req, second) {
			t.Fatalf("decoded twice, two answers:\n%+v\n%+v", req, second)
		}
	})
}

// batchSpec turns fuzz bytes into a tar stream of well-formed headers, so the
// search reaches the route's own rules instead of stopping at the tar reader:
// per entry a type selector, a name length and name, a body length. names
// lists what each regular entry carried, in order.
func batchSpec(spec []byte) (stream []byte, bodies map[string][]int) {
	types := []byte{tar.TypeReg, tar.TypeReg, tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeFifo, tar.TypeChar}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	bodies = map[string][]int{}
	for len(spec) >= 3 {
		typ, n := types[int(spec[0])%len(types)], int(spec[1])
		spec = spec[2:]
		if n > len(spec)-1 {
			n = len(spec) - 1
		}
		name, size := string(spec[:n]), int(spec[n])
		spec = spec[n+1:]
		hdr := &tar.Header{Name: name, Typeflag: typ, Mode: 0o644}
		switch typ {
		case tar.TypeReg:
			hdr.Size = int64(size)
		case tar.TypeSymlink, tar.TypeLink:
			hdr.Linkname = "/etc/passwd"
		}
		if tw.WriteHeader(hdr) != nil {
			break // a name tar cannot carry ends the stream where it stands
		}
		if typ == tar.TypeReg {
			tw.Write(bytes.Repeat([]byte{'x'}, size))
			bodies[relPath(name)] = append(bodies[relPath(name)], size)
		}
	}
	tw.Flush()
	return buf.Bytes(), bodies
}

// ownerReq sends one request as the seeded admin.
func ownerReq(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A batch goes through the whole route: its answer is a 200 or a 4xx, every
// file it reports is a path the share may hold with the size an entry of that
// name carried, the share's folder holds regular files and directories only,
// and nothing stays staged once the request is answered.
func FuzzUploadBatch(f *testing.F) {
	entry := func(typ byte, name string, size byte) []byte {
		return append(append([]byte{typ, byte(len(name))}, name...), size)
	}
	f.Add(append(entry(0, "a.txt", 3), entry(0, "dir/b.txt", 200)...))
	f.Add(append(entry(3, "dir/", 0), entry(0, "dir/c", 1)...))
	f.Add(append(entry(0, "ok.txt", 1), entry(4, "link", 0)...))
	f.Add(append(entry(0, "../up", 1), entry(0, "/abs", 1)...))
	f.Add(append(entry(0, "same", 1), entry(0, "same", 2)...))
	f.Add(append(entry(0, "SAME", 1), entry(0, "same", 2)...))
	f.Add(entry(0, "café.txt", 4))
	f.Add(entry(0, strings.Repeat("d/", 40)+"deep", 1))
	f.Add(entry(0, "a/./b//c", 0))
	f.Add(entry(0, ".", 0))

	b := testBackend(f)
	h := New(b, "2.0.0", testDomain(f), nil)
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(os.Stderr) })
	f.Fuzz(func(t *testing.T, spec []byte) {
		rec := ownerReq(h, "POST", "/api/shares", `{"name":"fuzz"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create → %d %s", rec.Code, rec.Body)
		}
		var created struct{ ID string }
		unmarshal(t, rec, &created)
		defer ownerReq(h, "DELETE", "/api/shares/"+created.ID, "")

		stream, bodies := batchSpec(spec)
		rec = postBatch(t, h, created.ID, testToken, stream, "")
		if rec.Code != http.StatusOK && (rec.Code < 400 || rec.Code > 499) {
			t.Fatalf("batch → %d %s", rec.Code, rec.Body)
		}
		var out struct {
			Files     []fileOut `json:"files"`
			Committed int       `json:"committed"`
		}
		unmarshal(t, rec, &out)
		if out.Committed != len(out.Files) {
			t.Fatalf("committed %d, listed %d", out.Committed, len(out.Files))
		}
		dir, err := b.FS.ShareDir(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range out.Files {
			if !shareid.ValidNewRelPath(file.Path) || file.Path != relPath(file.Path) {
				t.Fatalf("committed the path %q", file.Path)
			}
			// A volume that folds case stores two spellings as one file, so
			// the size may be that of an entry spelled another way.
			var carried []int
			for name, sizes := range bodies {
				if strings.EqualFold(name, file.Path) {
					carried = append(carried, sizes...)
				}
			}
			if !slices.Contains(carried, int(file.Size)) {
				t.Fatalf("%q committed with %d bytes; its entries carried %v", file.Path, file.Size, carried)
			}
			if !shareid.ValidSlug(file.Slug) {
				t.Fatalf("%q has the slug %q", file.Path, file.Slug)
			}
			info, err := os.Lstat(filepath.Join(dir, "files", filepath.FromSlash(file.Path)))
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("%q is reported committed and is not a file in the share: %v", file.Path, err)
			}
		}
		walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && !d.Type().IsRegular() {
				t.Fatalf("%s is neither a file nor a directory", p)
			}
			if !d.IsDir() && filepath.Base(filepath.Dir(p)) == "parts" {
				t.Fatalf("%s is still staged after the answer", p)
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
			t.Fatal(walkErr)
		}
	})
}
