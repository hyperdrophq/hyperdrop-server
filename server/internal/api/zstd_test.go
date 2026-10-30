package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func zstdBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zw.Write([]byte(s))
	zw.Close()
	return buf.Bytes()
}

// putRaw sends a PUT with an arbitrary byte body and optional headers.
func putRaw(t *testing.T, h http.Handler, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Upload-Session", "zstd-test-session")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestZstdUpload(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	content := strings.Repeat("compressible text ", 200)

	rec := putRaw(t, h, "/api/shares/"+id+"/files/a.txt", zstdBytes(t, content),
		map[string]string{"Content-Encoding": "zstd", "Upload-Range": "0-" + strconv.Itoa(len(content)),
			"Upload-Total": strconv.Itoa(len(content))})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body)
	}
	var out struct {
		Size int64  `json:"size"`
		Slug string `json:"slug"`
	}
	unmarshal(t, rec, &out)
	if out.Size != int64(len(content)) { // ORIGINAL bytes, not wire bytes
		t.Fatalf("stored size %d, want %d", out.Size, len(content))
	}
	get := doReq(t, h, "GET", "/view/"+id+"/"+out.Slug, "", "")
	if get.Body.String() != content {
		t.Fatal("roundtrip mismatch")
	}
}

func TestZstdChunksResumeInOriginalBytes(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	content := strings.Repeat("resumable compressible ", 300)
	half := len(content) / 2
	total := strconv.Itoa(len(content))

	// Chunk 1: its own zstd stream, its range in ORIGINAL bytes.
	r1 := putRaw(t, h, "/api/shares/"+id+"/files/big.txt", zstdBytes(t, content[:half]),
		map[string]string{"Content-Encoding": "zstd", "Upload-Range": "0-" + strconv.Itoa(half), "Upload-Total": total})
	if r1.Code != http.StatusAccepted {
		t.Fatalf("chunk1 status %d body %s", r1.Code, r1.Body)
	}
	var part struct {
		Missing [][2]int64 `json:"missing"`
	}
	unmarshal(t, r1, &part)
	if len(part.Missing) != 1 || part.Missing[0] != [2]int64{int64(half), int64(len(content))} {
		t.Fatalf("missing after chunk1 = %v, want [[%d %d]] (original bytes)", part.Missing, half, len(content))
	}
	// Chunk 2: a fresh independent zstd stream for the rest.
	r2 := putRaw(t, h, "/api/shares/"+id+"/files/big.txt", zstdBytes(t, content[half:]),
		map[string]string{"Content-Encoding": "zstd", "Upload-Range": strconv.Itoa(half) + "-" + total, "Upload-Total": total})
	if r2.Code != http.StatusCreated {
		t.Fatalf("chunk2 status %d body %s", r2.Code, r2.Body)
	}
	var out struct {
		Size int64  `json:"size"`
		Slug string `json:"slug"`
	}
	unmarshal(t, r2, &out)
	if out.Size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", out.Size, len(content))
	}
	get := doReq(t, h, "GET", "/view/"+id+"/"+out.Slug, "", "")
	if get.Body.String() != content {
		t.Fatal("roundtrip mismatch")
	}
}

func TestZstdChunkChecksFreeDiskInOriginalBytes(t *testing.T) {
	// A chunk's stored size is its range's length whatever the transport
	// encoding, so the per-PUT free-disk check must fire even though the
	// zstd wire length says nothing about the stored size.
	b := testBackend(t)
	b.FS.ReservePercent = 10 // reserve = 10 GB of the 100 GB disk
	b.FS.DiskSpace = func(string) (int64, int64, error) { return 15 << 30, 100 << 30, nil }
	h := New(b, "2.0.0", testDomain(t), nil)
	id := createShare(t, h, "z")

	rec := putRaw(t, h, "/api/shares/"+id+"/files/big.bin", zstdBytes(t, "x"),
		map[string]string{"Content-Encoding": "zstd",
			"Upload-Range": "0-" + strconv.FormatInt(6<<30, 10), "Upload-Total": strconv.FormatInt(6<<30, 10)})
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d body %s, want 507", rec.Code, rec.Body)
	}
}

func TestZstdGarbageRejected(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	rec := putRaw(t, h, "/api/shares/"+id+"/files/x.bin", []byte("this is not zstd at all"),
		map[string]string{"Content-Encoding": "zstd"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage status = %d body %s, want 400", rec.Code, rec.Body)
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &e); e.Error == "" {
		t.Fatal("expected a JSON error body")
	}
}

func TestUnknownEncodingRejected(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	rec := putRaw(t, h, "/api/shares/"+id+"/files/x.bin", []byte("data"),
		map[string]string{"Content-Encoding": "br"})
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

// A stream declaring a window past zstdMaxWindow is refused before its
// decoder allocates the buffer that window needs; the reference client's
// encoder, at each of its levels, stays within it.
func TestZstdWindowIsBounded(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	encode := func(opts ...zstd.EOption) []byte {
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf, opts...)
		if err != nil {
			t.Fatal(err)
		}
		zw.Write([]byte("tiny"))
		zw.Close()
		return buf.Bytes()
	}
	headers := map[string]string{"Content-Encoding": "zstd", "Upload-Range": "0-4", "Upload-Total": "4"}
	// A frame header declaring a 32 MiB window (exponent 15 over the 1 KiB
	// base), then one 4-byte raw block.
	block := []byte{byte(1 | 4<<3), 0, 0, 'a', 'b', 'c', 'd'}
	mid := append([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 15 << 3}, block...)
	rec0 := putRaw(t, h, "/api/shares/"+id+"/files/mid-window", mid, headers)
	if rec0.Code != http.StatusBadRequest {
		t.Fatalf("a 32 MiB window = %d %s, want 400", rec0.Code, rec0.Body)
	}
	// A frame header declaring a 512 MiB window (exponent 19).
	windowed := append([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 19 << 3}, block...)
	rec := putRaw(t, h, "/api/shares/"+id+"/files/big-window", windowed, headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a 512 MiB window = %d %s, want 400", rec.Code, rec.Body)
	}
	// A single-segment frame has no window field: its content size, here
	// 1 GiB over a 4-byte raw block, is the window the decoder would buffer.
	single := append([]byte{0x28, 0xB5, 0x2F, 0xFD, 0xE0, 0, 0, 0, 0x40, 0, 0, 0, 0}, block...)
	rec = putRaw(t, h, "/api/shares/"+id+"/files/big-single", single, headers)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a 1 GiB single-segment frame = %d %s, want 400", rec.Code, rec.Body)
	}
	for _, level := range []zstd.EncoderLevel{zstd.SpeedFastest, zstd.SpeedDefault, zstd.SpeedBetterCompression} {
		rec := putRaw(t, h, "/api/shares/"+id+"/files/"+level.String(),
			encode(zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(level)), headers)
		if rec.Code != http.StatusCreated {
			t.Fatalf("level %s = %d %s", level, rec.Code, rec.Body)
		}
	}
}

// holdSlots takes n decoder slots and returns a function that frees them.
func holdSlots(n int) func() {
	for i := 0; i < n; i++ {
		zstdSlots <- struct{}{}
	}
	return func() {
		for i := 0; i < n; i++ {
			<-zstdSlots
		}
	}
}

func zstdTinyUpload(t *testing.T, h http.Handler, id, name string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
	zw.Write([]byte("tiny"))
	zw.Close()
	return putRaw(t, h, "/api/shares/"+id+"/files/"+name, buf.Bytes(),
		map[string]string{"Content-Encoding": "zstd", "Upload-Range": "0-4", "Upload-Total": "4"})
}

func TestANinthDecoderWaitsForASlot(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	defer holdSlots(cap(zstdSlots) - 1)()
	zstdSlots <- struct{}{}
	time.AfterFunc(50*time.Millisecond, func() { <-zstdSlots })
	rec := zstdTinyUpload(t, h, id, "ninth")
	if rec.Code != http.StatusCreated {
		t.Fatalf("a ninth upload = %d %s, want 201", rec.Code, rec.Body)
	}
}

func TestANinthDecoderAnswers503AfterTheWait(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	old := zstdSlotWait
	zstdSlotWait = 100 * time.Millisecond
	defer func() { zstdSlotWait = old }()
	release := holdSlots(cap(zstdSlots))
	defer release()
	rec := zstdTinyUpload(t, h, id, "ninth")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d %s, want 503", rec.Code, rec.Body)
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec.Body.String(), `"busy"`) {
		t.Fatalf("body %s lacks code busy", rec.Body)
	}
}

// A refused stream frees the slot it took.
func TestAZstdRefusalFreesItsSlot(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "z")
	putRaw(t, h, "/api/shares/"+id+"/files/g", []byte("not zstd at all"),
		map[string]string{"Content-Encoding": "zstd", "Upload-Range": "0-4", "Upload-Total": "4"})
	if n := len(zstdSlots); n != 0 {
		t.Fatalf("%d slots still held", n)
	}
}
