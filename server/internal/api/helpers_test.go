package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

func init() {
	metadb.BcryptCost = bcrypt.MinCost
}

// testAdminPassword is the seeded admin password (bcrypt.MinCost - this is a
// fixture, not a security boundary).
const testAdminPassword = "admin-test-pw"

// testBackend opens a fresh database and file layer in one temp dir and
// seeds the admin holding the constant bearer every test passes.
func testBackend(t *testing.T) Backend {
	t.Helper()
	return testBackendAt(t, t.TempDir())
}

// New returns the HTTP handler over b, as the tests build it: no
// visit-flusher goroutine, so the pending set flushes on demand
// (t.visits.flush()) or never, which a test that never calls Drain can live
// with. main.go builds the server with NewServer, which starts it.
func New(b Backend, version string, dom *domain.Manager, upd *ddns.Updater) http.Handler {
	return newHandler(b, version, dom, upd, Deployment{}).routes()
}

// testBackendAt is testBackend rooted at a caller-chosen directory, for a
// test that needs the data laid out where something else on disk expects it.
func testBackendAt(t *testing.T, dir string) Backend {
	t.Helper()
	db, err := metadb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs, err := sharefs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(metadb.DefaultAdminName, testAdminPassword, metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	execRaw(t, dir, `INSERT INTO tokens(id, username, sha256, label, created_at) VALUES('seeded', ?, ?, '', ?)`,
		metadb.DefaultAdminName, metadb.TokenHash(testToken), time.Now().UnixNano())
	fs.DiskSpace = func(string) (int64, int64, error) { return 1 << 40, 2 << 40, nil }
	return Backend{DB: db, FS: fs}
}

// execRaw runs one statement on the database file in dir through a handle
// of its own. The admin's device token is seeded this way because the store
// mints every token's value itself, and every test here sends testToken.
func execRaw(t *testing.T, dir, query string, args ...any) {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, metadb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

// testBackendWithRoots is testBackend with the server folders a linked share
// may serve from, which the handler needs before it is built: the roots gate
// every serve, so a test that links a fixture volume has to name it here
// rather than after the fact.
func testBackendWithRoots(t *testing.T, roots *linked.Roots) Backend {
	t.Helper()
	b := testBackend(t)
	b.Roots = roots
	return b
}

// seedUser creates a normal user with a known password and returns a device
// token for them.
func seedUser(t *testing.T, db *metadb.DB, name string) string {
	t.Helper()
	if _, err := db.CreateUser(name, name+"-pw", metadb.RoleUser, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	tok, err := db.MintToken(name, "test")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// commitFile stages and commits one file into a share the way an upload does:
// the bytes first, then the row.
func commitFile(t *testing.T, b Backend, id, rel, content string) {
	t.Helper()
	if _, err := b.FS.Write(id, rel, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	c, err := b.FS.Commit(id, rel, int64(len(content)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: id, Path: rel,
		Size: c.Size, SHA256: c.SHA256, Mime: c.Mime}); err != nil {
		t.Fatal(err)
	}
}

// newTestAPIParts is a handler plus the struct behind it, for a test that
// needs the request state a route keeps rather than only its routes (the
// inbox name claims in flight).
func newTestAPIParts(t *testing.T) (http.Handler, *handler) {
	t.Helper()
	hd := newHandler(testBackend(t), "2.0.0", testDomain(t), nil, Deployment{})
	return hd.routes(), hd
}

// testDomain is the domain manager most handler tests pass to New: TLS
// mode (a public IP) with no domain configured.
func testDomain(t *testing.T) *domain.Manager {
	t.Helper()
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	return dom
}

// testDDNS builds a ddns.Updater over a fresh state file, wired to a stub
// names service that answers every update the same way and counts how many
// times it was hit, which is what makes a heartbeat OBSERVABLE from a test
// that has no server-side log to read. It also answers /v1/claim, issuing
// whatever name it was asked for, so a caller that goes through Take (a PUT
// with no token) succeeds the same way a real, uncontested claim would. The
// updater is stopped in cleanup: a run loop still ticking after the test
// function returns races the ddns state's own writes against the harness
// removing the TempDir underneath it.
func testDDNS(t *testing.T) (*ddns.Updater, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/claim") {
			var in struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"name":"` + in.Name + `","fqdn":"` + ddns.FQDN(in.Name) +
				`","token":"claimed-tok","expiresAt":9000}`))
			return
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7","changed":true,"state":"active","expiresAt":0}`))
	}))
	t.Cleanup(srv.Close)
	s, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	addr := func(context.Context) (string, bool) { return "203.0.113.7", true }
	upd := ddns.NewUpdater(s, &ddns.Client{BaseURL: srv.URL}, addr)
	t.Cleanup(upd.Stop)
	return upd, &hits
}

// newTestAPIWithService builds a handler over a fresh store and domain
// manager, with its ddns updater talking to service instead of the real
// names service. The common base every test that needs to dictate exactly
// what a claim or update answers builds on, rather than each wiring its own
// store, ddns state file and updater.
func newTestAPIWithService(t *testing.T, service http.Handler) http.Handler {
	t.Helper()
	srv := httptest.NewServer(service)
	t.Cleanup(srv.Close)
	s, err := ddns.Load(filepath.Join(t.TempDir(), "ddns"))
	if err != nil {
		t.Fatal(err)
	}
	addr := func(context.Context) (string, bool) { return "203.0.113.7", true }
	upd := ddns.NewUpdater(s, &ddns.Client{BaseURL: srv.URL}, addr)
	t.Cleanup(upd.Stop)
	return New(testBackend(t), "2.0.0", testDomain(t), upd)
}

// newTestAPIRefusingClaims builds a handler whose names service refuses
// every claim with status and reason, the shape a real refusal has: the
// service's own status code and the reason in an "error" field.
func newTestAPIRefusingClaims(t *testing.T, status int, reason string) http.Handler {
	t.Helper()
	return newTestAPIWithService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"` + reason + `"}`))
	}))
}

func doReqWithHeader(t *testing.T, h http.Handler, method, path, header, value string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(header, value)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doReqWithBearerAndHeader is doReqWithHeader plus an Authorization bearer,
// for a route that needs both the caller's identity and an extra header.
func doReqWithBearerAndHeader(t *testing.T, h http.Handler, method, path, token, header, value string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set(header, value)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func doReqForm(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func unmarshal(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("bad JSON %s: %v", rec.Body, err)
	}
}

// errCode reads the machine-readable code out of an error body, which is
// what a client acts on; the wording beside it is for a person.
func errCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("decoding error body %q: %v", body, err)
	}
	return e.Code
}

// uploadFile PUTs one file into a share and requires the 201.
func uploadFile(t *testing.T, h http.Handler, token, id, relpath, content string) {
	t.Helper()
	rec := doReq(t, h, "PUT", "/api/shares/"+id+"/files/"+relpath, token, content)
	if rec.Code != 201 {
		t.Fatalf("upload %s: status %d body %s", relpath, rec.Code, rec.Body)
	}
}
