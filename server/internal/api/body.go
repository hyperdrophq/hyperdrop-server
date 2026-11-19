package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// decodeBody returns the request body, transparently zstd-decoded, and reports
// whether it was decoded: a decoded stream's Content-Length describes the WIRE
// bytes, so callers that care about the original length must discard it. The
// returned cleanup MUST be called; it returns the pooled decoder and its slot. On an error
// it has already written the response.
//
// Every route that accepts an encoded body goes through this, so the pool
// lifetime (that Reset(nil) before putting it back, which otherwise leaves a
// pooled decoder holding a reference to a finished request body) has exactly
// one implementation. A read of the returned body fails with a refusal
// (requestBody), never with a bare transport or decoder error.
func decodeBody(w http.ResponseWriter, r *http.Request) (body io.Reader, cleanup func(), decoded bool, err error) {
	src := &sourceBody{r: r.Body}
	switch enc := r.Header.Get("Content-Encoding"); enc {
	case "", "identity":
		return requestBody{r: src, src: src}, func() {}, false, nil
	case "zstd":
		if !takeZstdSlot(r) {
			w.Header().Set("Retry-After", "2")
			err := refuse(http.StatusServiceUnavailable, "busy",
				"The server is busy unpacking uploads, try again shortly.")
			writeRefusal(w, err)
			return nil, nil, false, err
		}
		zr := zstdDecoders.Get().(*zstd.Decoder)
		if err := zr.Reset(src); err != nil {
			zstdDecoders.Put(zr)
			<-zstdSlots
			err = requestBody{src: src, zstd: true}.refusal(err)
			writeRefusal(w, err)
			return nil, nil, false, err
		}
		return requestBody{r: zr, src: src, zstd: true}, func() {
			zr.Reset(nil) // drop the request-body reference before pooling
			zstdDecoders.Put(zr)
			<-zstdSlots
		}, true, nil
	default:
		writeError(w, http.StatusUnsupportedMediaType, "unsupported Content-Encoding "+enc)
		return nil, nil, false, errors.New("unsupported encoding")
	}
}

// takeZstdSlot takes a decoder slot, waiting up to zstdSlotWait for one; it
// reports false when the wait runs out or the client has gone.
func takeZstdSlot(r *http.Request) bool {
	select {
	case zstdSlots <- struct{}{}:
		return true
	default:
	}
	t := time.NewTimer(zstdSlotWait)
	defer t.Stop()
	select {
	case zstdSlots <- struct{}{}:
		return true
	case <-t.C:
	case <-r.Context().Done():
	}
	return false
}

// ErrBodyStalled is what a request body's Read answers once the client has
// kept the server waiting too long for too few bytes (the server's body
// deadline, which wraps every request body before it reaches a route).
var ErrBodyStalled = errors.New("request body stalled: the client sent too little for too long")

// errBadBody and errBodyIncomplete are the two ways an upload body fails on
// the client's side, each a refusal rather than a 500:
//
//   - 400 bad-body: the bytes arrived whole and are not what the request
//     says, a zstd stream that is corrupt or ends inside a frame;
//   - 408 body-incomplete: the bytes stopped arriving, cut by the stall
//     deadline, an idle deadline or the connection ending first. A client
//     that is still there asks where its upload stands and resends the rest.
func errBadBody(detail string) error {
	return refuse(http.StatusBadRequest, "bad-body", "the request body does not decode: "+detail)
}

func errBodyIncomplete(err error) error {
	if errors.Is(err, ErrBodyStalled) || errors.Is(err, os.ErrDeadlineExceeded) {
		return refuse(http.StatusRequestTimeout, "body-incomplete",
			"the request body stalled: the client sent too little for too long")
	}
	return refuse(http.StatusRequestTimeout, "body-incomplete", "the request body ended before it was whole")
}

// sourceBody is the request body as the client sends it, remembering the
// first error its Read answered other than the end of the body.
type sourceBody struct {
	r   io.Reader
	err error
}

func (s *sourceBody) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF && s.err == nil {
		s.err = err
	}
	return n, err
}

// requestBody reads r, which is src or a decoder over it, and answers any
// failure as errBodyIncomplete when src failed and as errBadBody when src
// ended cleanly and the decoder over it did not.
type requestBody struct {
	r    io.Reader
	src  *sourceBody
	zstd bool
}

func (b requestBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		err = b.refusal(err)
	}
	return n, err
}

func (b requestBody) refusal(err error) error {
	switch {
	case b.src.err != nil:
		return errBodyIncomplete(b.src.err)
	case b.zstd:
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return errBadBody("the zstd stream ends inside a frame")
		}
		return errBadBody("corrupt zstd stream: " + err.Error())
	}
	return errBodyIncomplete(err)
}

// readCapped reads r's whole body, which may be at most max bytes. A longer
// body, or a body that stops arriving, gets tooLarge written and reports
// false; http.MaxBytesReader also marks the connection to close, since the
// rest of the body is never read.
func readCapped(w http.ResponseWriter, r *http.Request, max int64, tooLarge func(http.ResponseWriter)) ([]byte, bool) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		tooLarge(w)
		return nil, false
	}
	return data, true
}

// decodeOptionalJSONBody is decodeJSONBody for a route whose body may be
// absent: an empty body leaves dst as it is and reports true.
func decodeOptionalJSONBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err == nil && len(data) > 0 {
		err = decodeRequest(data, dst)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, badJSONMessage(err))
		return false
	}
	return true
}

// decodeJSONBody reads a size-capped JSON body into dst, writing the 400
// itself and reporting false when it cannot: the mirror image of writeJSON
// and writeError (respond.go), so every handler reading a JSON body shares
// one size cap and one 400.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err == nil {
		err = decodeRequest(data, dst)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, badJSONMessage(err))
		return false
	}
	return true
}

// decodeRequest decodes one JSON request body into dst, refusing a field
// dst does not name and anything after the value, so a field this server
// does not speak (sent by a newer client that skipped its version gate) is a
// 400 instead of a field dropped in silence. Every JSON request body in this
// package is decoded here, directly or through decodeJSONBody
// (TestEveryRequestBodyIsDecodedStrictly), and every refusal is answered with
// badJSONMessage.
func decodeRequest(body []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

// badJSONMessage is the 400 for a body decodeRequest refused: a field this
// server does not speak is named, since a client or a hand-written body (a
// DDNS recipe) is fixed by reading it; anything else is plain invalid JSON.
func badJSONMessage(err error) string {
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return "invalid JSON: this server does not know the field " + field
	}
	return "invalid JSON"
}

// zstdDecoders pools stream decoders across compressed PUTs: building one
// per request is expensive; klauspost's documented reuse is Reset per stream.
// Pooled decoders are never Closed.
//
// Decoders are bounded in memory, not in CPU: decode measures 12 to 15 GB/s
// per core, ~100x what a 1 Gbit/s link delivers (BenchmarkUploadDecode). A
// decoder buffers twice the window a frame declares, so zstdMaxWindow bounds
// a frame's declared window and, as the decoder's memory bound, a
// single-segment frame's content size, which stands in for its window; and
// zstdSlots admits at most eight decoders at once, so decoder memory is
// capped at 8 x 16 MiB = 128 MiB however many uploads arrive.
var zstdDecoders = sync.Pool{New: func() any {
	zr, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(zstdMaxWindow), zstd.WithDecoderMaxMemory(zstdMaxWindow))
	return zr
}}

// zstdSlots holds one token per decoder in use. decodeBody takes one before
// it draws a decoder and returns it from its cleanup (or at once, on a
// refusal); a request that finds all eight taken waits up to zstdSlotWait,
// then answers 503 busy.
var zstdSlots = make(chan struct{}, 8)

// zstdSlotWait is how long a compressed upload waits for a decoder slot.
var zstdSlotWait = 20 * time.Second

// zstdMaxWindow is the largest window a compressed upload may declare: twice
// the 8 MiB the reference client's encoder uses at every level
// (core/api compress.go), so a stream past it is refused as a bad request.
const zstdMaxWindow = 16 << 20
