package api

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
)

// An edit wrong in two ways gets ONE answer, and which one is part of the
// route: each row breaks two of applyEdit's checks (or the handler's
// password rule ahead of them) and pins the status, code and message the
// earlier check answers. No refused edit changes the share it names.
func TestAnEditWrongTwiceAnswersItsFirstRefusal(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	plain := createShareBody(t, h, `{"name":"plain"}`)
	uploadFile(t, h, testToken, plain, "a.txt", "text")
	text := createShareBody(t, h, `{"name":"Note","text":true}`)
	inbox := createInbox(t, h, `{"receive":true,"name":"in"}`)
	linkedID := createShareBody(t, h, `{"name":"trip","source":"photo/2024"}`)
	pending := createShareBody(t, h, `{"name":"p","files":[{"path":"a.jpg","size":1}]}`)
	longNote := strings.Repeat("n", inboxNoteLimit+1)
	// A scheduled expiry for the last row's cancelPending to find.
	if rec := doReq(t, h, "PATCH", "/api/shares/"+pending, testToken, `{"expiresInSeconds":60,"applyInSeconds":3600}`); rec.Code != 200 {
		t.Fatalf("schedule: %d %s", rec.Code, rec.Body)
	}

	type answer struct {
		status int
		code   string
		msg    string
	}
	rows := []struct {
		name  string
		share string
		body  string
		want  answer
	}{
		{"a short password beats a bad name", plain,
			`{"password":"short","name":"a/b"}`,
			answer{400, "password-too-short", metadb.ErrPasswordTooShort.Error()}},
		{"nothing to change beats a negative duration", plain,
			`{"applyInSeconds":-1}`,
			answer{400, "", "nothing to change"}},
		{"a text share's opens beat its sources", text,
			`{"entry":"x","sources":[]}`,
			answer{409, "text-share", "a text share opens as its file: entry, media and listing cannot change"}},
		{"a text share's sources beat a bad name", text,
			`{"sources":[],"name":"a/b"}`,
			answer{409, "text-share", "a text share is one text file: it takes no server folder"}},
		{"a text share's linked edit beats a bad name", text,
			`{"linked":{"photo/2024":{"fixed":true}},"name":"a/b"}`,
			answer{409, "text-share", "a text share is one text file: it takes no server folder"}},
		{"an opens pair beats an inbox's sources", inbox,
			`{"media":true,"listing":true,"sources":[]}`,
			answer{400, "", "a gallery is not a file listing"}},
		{"an opens pair beats a bad source", plain,
			`{"media":true,"entry":"x","sources":["../bad"]}`,
			answer{400, "", "a gallery has no entry page: the gallery is the page"}},
		{"an inbox's sources beat a bad source", inbox,
			`{"sources":["../bad"]}`,
			answer{400, "source-exclusive", "an inbox takes no sources"}},
		{"an inbox's linked edit beats a long note", inbox,
			`{"linked":{"photo/2024":{}},"note":"` + longNote + `"}`,
			answer{400, "source-exclusive", "an inbox takes no sources"}},
		{"a missing source beats a note on a share", plain,
			`{"sources":["photo/2099"],"note":"x"}`,
			answer{404, "source-missing", "no such file or folder on the server"}},
		{"an inbox's gallery beats a negative cap", inbox,
			`{"media":true,"maxBytes":-1}`,
			answer{400, "", "an inbox takes no entry, gallery, listing, expiry, pin, links off or scheduled change"}},
		{"an inbox's links off beats a negative cap", inbox,
			`{"linksOff":true,"maxBytes":-1}`,
			answer{400, "", "an inbox takes no entry, gallery, listing, expiry, pin, links off or scheduled change"}},
		{"an inbox's sources beat its links off", inbox,
			`{"sources":[],"linksOff":true}`,
			answer{400, "source-exclusive", "an inbox takes no sources"}},
		{"a note on a share beats a gallery with no pictures", plain,
			`{"note":"x","media":true}`,
			answer{400, "", "closed, note, notify, seenAt, maxBytes and maxFiles apply to Receive Inboxes only"}},
		{"a gallery with no pictures beats a negative expiry", plain,
			`{"media":true,"expiresInSeconds":-1}`,
			answer{400, "no-pictures", "this share has no pictures, video or audio to show"}},
		{"a gallery still uploading beats a bad name", pending,
			`{"media":true,"name":"a/b"}`,
			answer{400, "share-incomplete", "this share is still uploading"}},
		{"a negative cap beats a long note", inbox,
			`{"maxFiles":-1,"note":"` + longNote + `"}`,
			answer{400, "", "negative cap"}},
		{"a long note beats a bad name", inbox,
			`{"note":"` + longNote + `","name":"a/b"}`,
			answer{400, "", fmt.Sprintf("note too long (limit %d characters)", inboxNoteLimit)}},
		{"a bad entry beats a negative expiry", plain,
			`{"entry":"../x","expiresInSeconds":-1}`,
			answer{400, "", "entry must be a relative path inside the share"}},
		{"a negative expiry beats a bad name", plain,
			`{"expiresInSeconds":-1,"name":"a/b"}`,
			answer{400, "", "negative duration"}},
		{"a negative delay beats a bad name", plain,
			`{"applyInSeconds":-1,"name":"a/b"}`,
			answer{400, "", "negative duration"}},
		{"a bad name beats a bad cancelPending", plain,
			`{"name":"a/b","cancelPending":"bogus"}`,
			answer{400, "", "a share name cannot contain /"}},
		{"a bad cancelPending beats a missing fixed source", linkedID,
			`{"cancelPending":"bogus","linked":{"photo/2099":{"fixed":true}}}`,
			answer{400, "", "cancelPending must be password, expiry, or all"}},
		{"an unclean hide beats the source after it", linkedID,
			`{"linked":{"photo/2024":{"hide":["../x"]},"photo/2099":{}}}`,
			answer{400, "bad-source", "hide must name a clean relative path: ../x"}},
		{"a source the request does not hold beats a colliding upload", pending,
			`{"sources":["photo/2024"],"linked":{"photo/2099":{"fixed":true}}}`,
			answer{400, "not-a-source", "not one of this share's sources: photo/2099"}},
		{"a colliding upload is refused before the cancel writes", pending,
			`{"sources":["photo/2024"],"linked":{"photo/2024":{"fixed":true}},"cancelPending":"all"}`,
			answer{400, "path-taken", "a source already lists under the name a.jpg"}},
	}
	reads := func() string {
		var all []string
		for _, id := range []string{plain, text, inbox, linkedID, pending} {
			all = append(all, doReq(t, h, "GET", "/api/shares/"+id, testToken, "").Body.String())
		}
		return strings.Join(all, "\n")
	}
	before := reads()
	for _, row := range rows {
		rec := doReq(t, h, "PATCH", "/api/shares/"+row.share, testToken, row.body)
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
	if after := reads(); after != before {
		t.Errorf("a refused edit changed a share:\nbefore %s\nafter  %s", before, after)
	}
}
