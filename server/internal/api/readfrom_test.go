package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readFromRecorder is a ResponseWriter that, like net/http's own, takes a body
// through ReadFrom, and records that it did.
type readFromRecorder struct {
	*httptest.ResponseRecorder
	readFrom bool
}

func (r *readFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.readFrom = true
	return io.Copy(struct{ io.Writer }{r.ResponseRecorder}, src)
}

// The wrappers every file route runs through pass a body on to the real
// writer's ReadFrom, which is net/http's sendfile path; hiding it makes every
// file go out through a buffered copy instead. The source is a LimitedReader,
// which is what http.ServeContent copies from.
func TestFileBodiesReachTheRealWritersReadFrom(t *testing.T) {
	inner := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	var w http.ResponseWriter = &statusRecorder{ResponseWriter: inner}
	w = &brandedNotFoundWriter{w: w, r: httptest.NewRequest("GET", "/view/x/y", nil), page: (&handler{}).notFoundPage}
	if _, err := io.CopyN(w, strings.NewReader("file bytes"), 10); err != nil {
		t.Fatal(err)
	}
	if !inner.readFrom {
		t.Fatal("the body did not reach the real writer's ReadFrom")
	}
	if got := inner.Body.String(); got != "file bytes" || inner.Code != http.StatusOK {
		t.Fatalf("body %q, status %d", got, inner.Code)
	}
}

// A refusal's body still goes through Write, where the log reads its code.
func TestARefusalBodyIsStillReadForItsCode(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.WriteHeader(http.StatusConflict)
	if _, err := io.Copy(rec, strings.NewReader(`{"code":"text-share"}`)); err != nil {
		t.Fatal(err)
	}
	if rec.code != "text-share" {
		t.Fatalf("code = %q, want text-share", rec.code)
	}
}
