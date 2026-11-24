package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// A create request wrong in two ways gets ONE answer, and which one is part
// of the route: each row breaks two of createShare's checks and pins the
// status, code and message the earlier check answers.
func TestACreateWrongTwiceAnswersItsFirstRefusal(t *testing.T) {
	h, b, vol := linkedTestAPI(t)
	for _, f := range []string{"photo/heics/a.jpg", "photo/heics/photo.heic"} {
		os.MkdirAll(filepath.Dir(filepath.Join(vol, f)), 0o755)
		os.WriteFile(filepath.Join(vol, f), []byte("x"), 0o644)
	}
	bob := seedUser(t, b.DB, "bob")
	bobRoots := []string{"photo/2024"}
	quota := int64(1000)
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: &bobRoots, QuotaBytes: &quota}); err != nil {
		t.Fatal(err)
	}
	b.FS.ReservePercent = 0

	deep := strings.Repeat("d/", shareid.MaxRelPathDepth) + "f.txt"
	manifest := func(paths ...string) string {
		var parts []string
		for _, p := range paths {
			parts = append(parts, fmt.Sprintf(`{"path":%q,"size":1}`, p))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	tooMany := make([]string, maxManifestFiles+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("f%d.txt", i)
	}
	tooMany[0] = deep
	longNote := strings.Repeat("n", inboxNoteLimit+1)

	type answer struct {
		status int
		code   string
		msg    string
	}
	rows := []struct {
		name  string
		token string
		body  string
		want  answer
	}{
		{"an oversized body beats an unknown field", testToken,
			`{"bogus":"` + strings.Repeat("x", createBodyLimit) + `"}`,
			answer{413, "body-too-large", fmt.Sprintf("share request too large (limit %d bytes): send at most %d files in the manifest", createBodyLimit, maxManifestFiles)}},
		{"an unknown field beats a manifest over the cap", testToken,
			`{"bogus":1,"files":` + manifest(tooMany...) + `}`,
			answer{400, "", `invalid JSON: this server does not know the field "bogus"`}},
		{"a manifest over the cap beats a too-deep path", testToken,
			`{"files":` + manifest(tooMany...) + `}`,
			answer{413, "manifest-too-big", fmt.Sprintf("manifest has %d files, the limit is %d: create the share without a manifest and upload into it", maxManifestFiles+1, maxManifestFiles)}},
		{"a too-deep path beats a bad entry", testToken,
			`{"entry":"../x","files":` + manifest(deep) + `}`,
			answer{400, "path-too-deep", fmt.Sprintf("a path holds at most %d folders and a name", shareid.MaxRelPathDepth)}},
		{"a bad entry beats a bad name", testToken,
			`{"entry":"../x","name":"a/b"}`,
			answer{400, "", "entry must be a relative path inside the share"}},
		{"a bad name beats a gallery that is a listing", testToken,
			`{"name":"a/b","media":true,"listing":true}`,
			answer{400, "", "a share name cannot contain /"}},
		{"a bad name beats a cap on a share", testToken,
			`{"name":"a/b","maxFiles":3}`,
			answer{400, "", "a share name cannot contain /"}},
		{"a text inbox beats source and sources", testToken,
			`{"text":true,"receive":true,"name":"n","source":"photo/2024","sources":["photo/2024"]}`,
			answer{400, "", "a share is a text share or an inbox, never both"}},
		{"a text gallery beats a bad source", testToken,
			`{"text":true,"media":true,"source":"../x"}`,
			answer{400, "", "a text share opens as its file and takes no entry, gallery or listing"}},
		{"a gallery inbox beats its missing name", testToken,
			`{"media":true,"receive":true}`,
			answer{400, "", "a share is a gallery or an inbox, never both"}},
		{"an inbox with an entry beats its missing name", testToken,
			`{"receive":true,"entry":"index.html"}`,
			answer{400, "", "an inbox has no entry page: its content is never served publicly"}},
		{"a page that is a listing beats a note on a share", testToken,
			`{"listing":true,"entry":"index.html","note":"hi"}`,
			answer{400, "", "a page is not a file listing"}},
		{"source and sources beat an inbox", testToken,
			`{"source":"photo/2024","sources":["public-share"],"receive":true,"name":"n"}`,
			answer{400, "bad-source", "give source or sources, not both"}},
		{"an inbox with a source beats a bad source", testToken,
			`{"receive":true,"name":"n","source":"../x"}`,
			answer{400, "source-exclusive", "an inbox takes no sources"}},
		{"a bad source shape beats a forbidden source after it", testToken,
			`{"sources":["../x","homes/alice"]}`,
			answer{400, "bad-source", "source must be a clean root-relative path"}},
		{"a forbidden source beats a bad shape after it", testToken,
			`{"sources":["homes/alice","../x"]}`,
			answer{403, "source-forbidden", "no folder this server shares holds homes/alice"}},
		{"a missing source beats two sources of one name", testToken,
			`{"sources":["photo/2099","photo/2024","photo/2024"]}`,
			answer{404, "source-missing", "no such file or folder on the server"}},
		{"two sources of one name beat a colliding upload", testToken,
			`{"sources":["photo/2024","photo/2024"],"files":` + manifest("a.jpg") + `}`,
			answer{400, "bad-source", "two sources share the name 2024"}},
		{"an account's forbidden source beats a note on a share", bob,
			`{"source":"public-share","note":"hi"}`,
			answer{403, "source-forbidden", "this account may not share from public-share"}},
		{"a forbidden source beats a colliding upload", bob,
			`{"source":"public-share","files":` + manifest("index.html") + `}`,
			answer{403, "source-forbidden", "this account may not share from public-share"}},
		{"a missing source beats a cap on a share", testToken,
			`{"source":"photo/2099","maxBytes":5}`,
			answer{404, "source-missing", "no such file or folder on the server"}},
		{"a colliding upload beats a note on a share", testToken,
			`{"source":"photo/2024","files":` + manifest("a.jpg") + `,"note":"hi"}`,
			answer{400, "path-taken", "a source already lists under the name a.jpg"}},
		{"an inbox's manifest beats its missing name", testToken,
			`{"receive":true,"files":` + manifest("a.txt") + `}`,
			answer{400, "", "an inbox takes no manifest, entry, expiry, reservation or links off"}},
		{"an inbox's negative expiry beats its missing name", testToken,
			`{"receive":true,"expiresInSeconds":-5}`,
			answer{400, "", "an inbox takes no manifest, entry, expiry, reservation or links off"}},
		{"an inbox's reservation beats a long note", testToken,
			`{"receive":true,"name":"n","reserveBytes":5,"note":"` + longNote + `"}`,
			answer{400, "", "an inbox takes no manifest, entry, expiry, reservation or links off"}},
		{"an inbox's links off beats its missing name", testToken,
			`{"receive":true,"linksOff":true}`,
			answer{400, "", "an inbox takes no manifest, entry, expiry, reservation or links off"}},
		{"an inbox's source beats its links off", testToken,
			`{"receive":true,"name":"n","source":"photo/2024","linksOff":true}`,
			answer{400, "source-exclusive", "an inbox takes no sources"}},
		{"an inbox's missing name beats a long note", testToken,
			`{"receive":true,"note":"` + longNote + `"}`,
			answer{400, "", "an inbox needs a name"}},
		{"a long note beats a negative cap", testToken,
			`{"receive":true,"name":"n","note":"` + longNote + `","maxBytes":-1}`,
			answer{400, "", fmt.Sprintf("note too long (limit %d characters)", inboxNoteLimit)}},
		{"a negative cap beats a short password", testToken,
			`{"receive":true,"name":"n","maxFiles":-1,"password":"short"}`,
			answer{400, "", "negative cap"}},
		{"a cap on a share beats a short password", testToken,
			`{"maxFiles":5,"password":"short"}`,
			answer{400, "", "note and caps apply to Receive Inboxes only"}},
		{"a note on a share beats a text share with a source", testToken,
			`{"note":"hi","text":true,"source":"photo/2024"}`,
			answer{400, "", "note and caps apply to Receive Inboxes only"}},
		{"a short password beats a text share with a source", testToken,
			`{"password":"short","text":true,"source":"photo/2024"}`,
			answer{400, "password-too-short", metadb.ErrPasswordTooShort.Error()}},
		{"a short password beats a text share's second file", testToken,
			`{"password":"short","text":true,"files":` + manifest("a.txt", "b.txt") + `}`,
			answer{400, "password-too-short", metadb.ErrPasswordTooShort.Error()}},
		{"a text share's source beats its second file", testToken,
			`{"text":true,"source":"photo/2024","files":` + manifest("x.txt", "y.txt") + `}`,
			answer{400, "", "bad request: a text share holds one uploaded file, never a server folder"}},
		{"a text share's second file beats a negative expiry", testToken,
			`{"text":true,"expiresInSeconds":-5,"files":` + manifest("a.txt", "b.txt") + `}`,
			answer{400, "", "bad request: a text share's manifest declares at most one file, not 2"}},
		{"a linked gallery's pending upload beats its reservation", testToken,
			`{"source":"photo/2024","media":true,"reserveBytes":1125899906842624,"files":` + manifest("new.jpg") + `}`,
			answer{400, "share-incomplete", "this share is still uploading"}},
		{"an unplayable linked gallery beats its reservation", testToken,
			`{"source":"photo/heics","media":true,"reserveBytes":1125899906842624}`,
			answer{400, "not-gallery-playable", "no browser can show photo.heic without converting it first"}},
		{"a reservation past the quota, with a negative expiry", bob,
			`{"name":"r","reserveBytes":2000,"expiresInSeconds":-5}`,
			answer{507, "quota", "storage quota exceeded: this account holds 0 of 1000 bytes and its uploads and previews 0 more"}},
	}
	listings := func() string {
		return doReq(t, h, "GET", "/api/shares", testToken, "").Body.String() +
			doReq(t, h, "GET", "/api/shares", bob, "").Body.String()
	}
	before := listings()
	for _, row := range rows {
		rec := doReq(t, h, "POST", "/api/shares", row.token, row.body)
		var got map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Errorf("%s: %d %q is not a JSON error", row.name, rec.Code, rec.Body.String())
			continue
		}
		want := map[string]string{"error": row.want.msg}
		if row.want.code != "" {
			want["code"] = row.want.code
		}
		if rec.Code != row.want.status || !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %d %v\nwant %d %v", row.name, rec.Code, got, row.want.status, want)
		}
	}
	if after := listings(); after != before {
		t.Errorf("a refused create left a share behind:\nbefore %s\nafter  %s", before, after)
	}
}

// Validation runs before the creation limiter, so a refused request spends
// no token; past the limit, the limiter answers before the password rule.
func TestACreateIsValidatedBeforeTheLimiterAndLimitedBeforeItsPassword(t *testing.T) {
	b := testBackend(t)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	hd.limits.create = newTokenLimiter(1, 1)
	h, um := hd.routes(), b.DB
	carol := seedUser(t, um, "carol")
	if rec := doReq(t, h, "POST", "/api/shares", carol, `{}`); rec.Code != http.StatusCreated {
		t.Fatalf("the share that spends the token: %d %s", rec.Code, rec.Body)
	}
	for _, row := range []struct{ body, want string }{
		{`{"entry":"../x","password":"short"}`, `400 {"error":"entry must be a relative path inside the share"}`},
		{`{"password":"short"}`, `429 {"code":"rate-limited","error":"too many shares created just now, wait a moment and try again"}`},
	} {
		rec := doReq(t, h, "POST", "/api/shares", carol, row.body)
		var got map[string]string
		unmarshal(t, rec, &got)
		out, _ := json.Marshal(got)
		if g := fmt.Sprintf("%d %s", rec.Code, out); g != row.want {
			t.Errorf("%s: %s, want %s", row.body, g, row.want)
		}
	}
}

// A negative expiresInSeconds at creation is no expiry: the share is made
// and carries no expiresAt (the update routes refuse the same value).
func TestACreateWithANegativeExpiryHasNoExpiry(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/shares", testToken, `{"name":"x","expiresInSeconds":-5}`)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), `"expiresAt"`) {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
}
