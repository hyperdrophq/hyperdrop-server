package api

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/shareid"
)

// A publish commit wrong in two ways gets ONE answer, and which one is part
// of the route: each row breaks two of publishCommit's checks and pins the
// status and body the earlier check answers. No refused commit closes its
// publish or changes its share.
func TestACommitWrongTwiceAnswersItsFirstRefusal(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	plain := createShare(t, h, "s")
	plainPid := openPublish(t, h, testToken, plain)
	stageFile(t, h, plain, plainPid, "a.txt", "A")
	linkedID := createShareBody(t, h, `{"name":"trip","source":"photo/2024"}`)
	linkedPid := openPublish(t, h, testToken, linkedID)
	// No route opens a publish on a text share; the commit still refuses one.
	text := createShareBody(t, h, `{"name":"Note","text":true}`)
	textPid := shareid.NewPublishID()
	if err := b.FS.OpenStage(text, textPid, metadb.DefaultAdminName); err != nil {
		t.Fatal(err)
	}

	deep := strings.Repeat("d/", shareid.MaxRelPathDepth) + "f.txt"
	tooMany := make([]string, publishMaxFiles+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("f/%05d.txt", i)
	}
	tooMany[0] = deep
	tooManyBody, _ := json.Marshal(map[string]any{"files": tooMany})
	jsonList := func(paths ...string) string {
		out, _ := json.Marshal(paths)
		return string(out)
	}
	deepJSON, _ := json.Marshal(deep)
	twoSpellings := `{"caf\u00e9.txt":"","cafe\u0301.txt":""}`

	rows := []struct {
		name  string
		share string
		pid   string
		body  string
		want  map[string]any
		code  int
	}{
		{"an unknown publish beats an unknown field", plain, "nope",
			`{"bogus":1}`,
			map[string]any{"code": "no-such-publish", "error": "no such publish is open on this share: it was committed, aborted or swept, or never opened"}, 404},
		{"an unknown field beats an empty commit", plain, plainPid,
			`{"bogus":1}`,
			map[string]any{"error": `invalid JSON: this server does not know the field "bogus"`}, 400},
		{"too many files beat a deep path", plain, plainPid,
			string(tooManyBody),
			map[string]any{"error": fmt.Sprintf("a publish holds at most %d files to publish and as many to delete", publishMaxFiles)}, 413},
		{"too many deletes beat an unclean file", plain, plainPid,
			`{"files":["../x"],"delete":` + jsonList(tooMany...) + `,"base":{}}`,
			map[string]any{"error": fmt.Sprintf("a publish holds at most %d files to publish and as many to delete", publishMaxFiles)}, 413},
		{"an empty commit beats a base naming more paths", plain, plainPid,
			`{"base":{"a.txt":""}}`,
			map[string]any{"error": "a commit names files to publish or delete"}, 400},
		{"a base naming more paths beats a deep path", plain, plainPid,
			`{"files":[` + string(deepJSON) + `],"base":{"a.txt":"","b.txt":""}}`,
			map[string]any{"error": "base names more paths than the commit publishes and deletes"}, 400},
		{"a deep path beats an unclean path before it", plain, plainPid,
			`{"files":["../x",` + string(deepJSON) + `]}`,
			map[string]any{"code": "path-too-deep", "error": fmt.Sprintf("a path holds at most %d folders and a name", shareid.MaxRelPathDepth)}, 400},
		{"an unclean path beats a path named twice after it", plain, plainPid,
			`{"files":["../x","a.txt","a.txt"]}`,
			map[string]any{"error": "not a clean relative path: ../x"}, 400},
		{"a path named twice beats an unclean path after it", plain, plainPid,
			`{"files":["a.txt","a.txt","../x"]}`,
			map[string]any{"error": "a.txt is named twice in one commit"}, 400},
		{"an unclean delete beats a path to publish and delete", plain, plainPid,
			`{"files":["a.txt"],"delete":["../x","a.txt"]}`,
			map[string]any{"error": "not a clean relative path: ../x"}, 400},
		{"a path named twice beats a base path named twice", plain, plainPid,
			`{"files":["a.txt","b.txt"],"delete":["a.txt"],"base":` + twoSpellings + `}`,
			map[string]any{"error": "a.txt is named twice in one commit"}, 400},
		{"a base path named twice beats a text share", text, textPid,
			`{"files":["x.txt","y.txt"],"base":` + twoSpellings + `}`,
			map[string]any{"error": "caf\u00e9.txt is named twice in base"}, 400},
		{"a text share beats a file not staged", text, textPid,
			`{"files":["x.txt"]}`,
			map[string]any{"code": "text-share", "error": "a text share holds one file: replace it rather than publishing into it"}, 409},
		{"a linked collision beats a file not staged", linkedID, linkedPid,
			`{"files":["a.jpg","new.jpg"]}`,
			map[string]any{"code": "path-taken", "error": "a source already lists under the name a.jpg"}, 400},
		{"a file not staged beats a stale base", plain, plainPid,
			`{"files":["missing.txt","a.txt"],"base":{"a.txt":"0000"}}`,
			map[string]any{"code": "publish-incomplete", "error": "1 of the files to publish have no finished upload in it", "missing": []any{"missing.txt"}}, 409},
	}
	reads := func() string {
		var all []string
		for _, id := range []string{plain, linkedID, text} {
			all = append(all, doReq(t, h, "GET", "/api/shares/"+id, testToken, "").Body.String())
		}
		return strings.Join(all, "\n")
	}
	before := reads()
	for _, row := range rows {
		rec := commitPublish(t, h, row.share, row.pid, row.body)
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Errorf("%s: %d %q is not a JSON error", row.name, rec.Code, rec.Body.String())
			continue
		}
		if rec.Code != row.code || !reflect.DeepEqual(got, row.want) {
			t.Errorf("%s:\n got %d %v\nwant %d %v", row.name, rec.Code, got, row.code, row.want)
		}
	}
	if after := reads(); after != before {
		t.Errorf("a refused commit changed a share:\nbefore %s\nafter  %s", before, after)
	}
	for _, p := range []struct{ id, pid string }{{plain, plainPid}, {linkedID, linkedPid}, {text, textPid}} {
		if !b.FS.StageExists(p.id, p.pid) {
			t.Errorf("a refused commit closed publish %s of %s", p.pid, p.id)
		}
	}
}
