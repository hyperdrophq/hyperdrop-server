package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"hyperdrop/server/internal/shareid"
)

// statusRecorder captures the status and the error code writeRefusal put in
// the body, so a refusal is logged with what the client saw.
type statusRecorder struct {
	http.ResponseWriter
	status int
	code   string
	wrote  bool
}

func (s *statusRecorder) WriteHeader(c int) {
	if !s.wrote {
		s.status, s.wrote = c, true
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	if s.status >= 400 && s.code == "" {
		var body struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(b, &body) == nil {
			s.code = body.Code
		}
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ReadFrom hands a successful body to the real writer's own ReadFrom, which
// is what lets http.ServeContent send a file with sendfile: io.Copy into a
// wrapper without one falls back to a buffered copy. A refusal's body still
// goes through Write, where its error code is read.
func (s *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	if s.status >= 400 {
		return io.Copy(struct{ io.Writer }{s}, src)
	}
	return readFrom(s.ResponseWriter, src)
}

// readFrom copies src into w through w's own ReadFrom when it has one.
func readFrom(w io.Writer, src io.Reader) (int64, error) {
	if rf, ok := w.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{w}, src)
}

// logResponses writes one log line per response of 400 or more, naming the
// route by its mux PATTERN and never by its path: a path carries a relpath,
// which is a file name a stranger uploaded or the owner shared, and the log
// is what an operator pastes to support. The share id is added only when it
// is well-formed, for the same reason.
func logResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status < 400 {
			return
		}
		// The mux sets Pattern and the path values on this same request.
		pattern := r.Pattern
		if pattern == "" {
			pattern = "(unmatched)"
		}
		line := fmt.Sprintf("http status=%d method=%s route=%s", rec.status, r.Method, pattern)
		if pattern == catchAllRoute || pattern == "(unmatched)" {
			unmatched.log(line, r)
			return
		}
		if rec.code != "" {
			line += " code=" + rec.code
		}
		if id := r.PathValue("id"); id != "" && shareid.ValidID(id) {
			line += " share=" + id
		}
		log.Print(line)
	})
}

// catchAllRoute is the pattern of the not-found page, which answers every
// path the server has no route for.
const catchAllRoute = "GET /"

// unmatchedWindow is how long a source's requests for paths the server does
// not have are counted rather than logged.
const unmatchedWindow = time.Minute

// unmatchedSourcesMax bounds the sources remembered at once; past it the
// oldest windows are forgotten, so a sweep across many addresses cannot grow
// the map.
const unmatchedSourcesMax = 1024

// unmatchedLog writes the requests for paths the server does not have (the
// not-found page, a method no route takes) with the address and user agent
// they came from, which is what tells a scanner from a broken client, at
// most once a minute per address: the first one logs, the rest of that
// minute are counted, and the next line after it carries the count as
// suppressed=N. The path is never logged.
type unmatchedLog struct {
	mu      sync.Mutex
	now     func() time.Time
	sources map[string]*unmatchedSource
}

type unmatchedSource struct {
	since      time.Time
	suppressed int
}

var unmatched = &unmatchedLog{now: time.Now, sources: map[string]*unmatchedSource{}}

// resetUnmatchedLog forgets every source and reads the time from now.
func resetUnmatchedLog(now func() time.Time) {
	unmatched.mu.Lock()
	defer unmatched.mu.Unlock()
	unmatched.now, unmatched.sources = now, map[string]*unmatchedSource{}
}

func (u *unmatchedLog) log(line string, r *http.Request) {
	peer := clientIP(r)
	u.mu.Lock()
	now := u.now()
	src := u.sources[peer]
	if src != nil && now.Sub(src.since) < unmatchedWindow {
		src.suppressed++
		u.mu.Unlock()
		return
	}
	suppressed := 0
	if src != nil {
		suppressed = src.suppressed
	}
	if len(u.sources) >= unmatchedSourcesMax {
		for k, v := range u.sources {
			if now.Sub(v.since) >= unmatchedWindow {
				delete(u.sources, k)
			}
		}
	}
	if len(u.sources) < unmatchedSourcesMax || src != nil {
		u.sources[peer] = &unmatchedSource{since: now}
	}
	u.mu.Unlock()
	line += fmt.Sprintf(" peer=%s ua=%q", peer, userAgentText(r.UserAgent()))
	if suppressed > 0 {
		line += fmt.Sprintf(" suppressed=%d", suppressed)
	}
	log.Print(line)
}

// userAgentText is a user agent as a log can carry it: at most 120
// characters, double quotes turned single so the quoted field stays one.
func userAgentText(ua string) string {
	if len(ua) > 120 {
		ua = ua[:120]
	}
	return strings.ReplaceAll(ua, `"`, "'")
}

// recoverPanics turns a handler panic into a logged 500 rather than a
// dropped connection, so the log names what went wrong. http.ErrAbortHandler
// is net/http's own way of dropping a connection and is re-raised.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Printf("panic: %v method=%s\n%s", v, r.Method, debug.Stack())
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
