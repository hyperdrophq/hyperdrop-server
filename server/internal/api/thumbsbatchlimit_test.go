package api

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
)

// sidecarStream streams a tar of one good tile for slug, then a filler entry
// sized so the stream reaches the per-request limit after `past` more bytes,
// then another tile, without holding the stream in memory.
func sidecarStream(t *testing.T, slug string, tile []byte, past int64) io.Reader {
	t.Helper()
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		write := func(name string, size int64, r io.Reader) error {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
				return err
			}
			_, err := io.CopyN(tw, r, size)
			return err
		}
		padded := (int64(len(tile)) + 511) / 512 * 512
		filler := sidecarBatchMaxBytes - 512 - padded - 512 + past
		var err error
		if err = write(slug+".jpg", int64(len(tile)), bytes.NewReader(tile)); err == nil {
			if err = write("filler.bin", filler, zeros{}); err == nil {
				err = write(slug+".jpg", int64(len(tile)), bytes.NewReader(tile))
			}
		}
		if err == nil {
			err = tw.Close()
		}
		pw.CloseWithError(err)
	}()
	return pr
}

// A tile batch past the per-request byte limit is refused with 413 and says
// how many tiles it stored before the limit, wherever the limit falls: on a
// boundary between two entries, or inside one.
func TestThumbBatchPastTheByteLimitIsRefusedWithWhatItStored(t *testing.T) {
	h := newTestAPI(t)
	id, slug := mediaShareWithFile(t, h, "a.jpg", "photo")
	tile := aJPEG(t, 8, 8)
	for _, past := range []int64{0, 1, 700} {
		req := httptest.NewRequest("POST", "/api/shares/"+id+"/thumbs", sidecarStream(t, slug, tile, past))
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var res sidecarBatchResult
		unmarshal(t, rec, &res)
		if rec.Code != 413 || res.Stored != 1 || res.Error == "" {
			t.Errorf("limit %d bytes past the boundary = %d %+v, want 413 with the one tile stored", past, rec.Code, res)
		}
	}
}
