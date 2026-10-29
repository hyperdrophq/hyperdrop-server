package api

import (
	"net/http"
	"strings"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

type revokedView struct {
	ID            string `json:"id"`
	SourceMissing bool   `json:"sourceMissing"`
	Files         []struct {
		Path string `json:"path"`
		Slug string `json:"slug"`
	} `json:"files"`
	Linked map[string]struct {
		Revoked *struct {
			At    string `json:"at"`
			Files *int   `json:"files"`
		} `json:"revoked"`
	} `json:"linked"`
}

// A non-admin with the given allowlist, signed in.
func grantedUser(t *testing.T, h http.Handler, name string, roots ...string) string {
	t.Helper()
	body := `{"username":"` + name + `","password":"pw-` + name + `-secret","quotaBytes":0,"sourceRoots":["` +
		strings.Join(roots, `","`) + `"]}`
	if len(roots) == 0 {
		body = `{"username":"` + name + `","password":"pw-` + name + `-secret","quotaBytes":0}`
	}
	if rec := doReq(t, h, "POST", "/api/users", testToken, body); rec.Code != 201 {
		t.Fatalf("create %s: %d %s", name, rec.Code, rec.Body)
	}
	token, code := login(t, h, name, "pw-"+name+"-secret")
	if code != 200 {
		t.Fatalf("login %s: %d", name, code)
	}
	return token
}

func slugOf(t *testing.T, v revokedView, path string) string {
	t.Helper()
	for _, f := range v.Files {
		if f.Path == path {
			return f.Slug
		}
	}
	t.Fatalf("no %s in %+v", path, v.Files)
	return ""
}

func TestRevokingAFolderUnpublishesItsEntriesAndRestoringBringsTheLinksBack(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"trip"}`), &made)
	slugA := slugOf(t, made, "a.jpg")
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 200 {
		t.Fatalf("download before: %d", rec.Code)
	}

	rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[]}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"revokes-shares"`) ||
		!strings.Contains(rec.Body.String(), `"source":"photo/2024"`) || !strings.Contains(rec.Body.String(), `"files":2`) {
		t.Fatalf("unconfirmed narrowing: %d %s", rec.Code, rec.Body)
	}
	after := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", "")
	if after.Code != 200 {
		t.Fatalf("a refused edit changed the share: %d", after.Code)
	}

	rec = doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[],"confirmRevoke":true}`)
	if rec.Code != 200 {
		t.Fatalf("confirmed narrowing: %d %s", rec.Code, rec.Body)
	}
	var revoked revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, bob, ""), &revoked)
	if len(revoked.Files) != 0 || !revoked.SourceMissing {
		t.Fatalf("revoked share = %+v, want no files and sourceMissing", revoked)
	}
	st := revoked.Linked["photo/2024"].Revoked
	if st == nil || st.At == "" || st.Files == nil || *st.Files != 2 {
		t.Fatalf("linked state = %+v", revoked.Linked)
	}
	// The whole share is unavailable: the public page says so and serves no bytes.
	rec = doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", "")
	if rec.Body.String() == "AAAA" || !(rec.Code == 404 || strings.Contains(rec.Body.String(), "not available on this server")) {
		t.Fatalf("revoked bytes served: %d %q", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, bob, ""); rec.Code != 404 {
		t.Fatalf("owner bearer fetch of a revoked entry: %d, want 404", rec.Code)
	}

	rec = doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["photo"]}`)
	if rec.Code != 200 {
		t.Fatalf("widening asks nothing: %d %s", rec.Code, rec.Body)
	}
	var restored revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, bob, ""), &restored)
	if len(restored.Linked) != 0 || slugOf(t, restored, "a.jpg") != slugA {
		t.Fatalf("restore = %+v, want the same slug back", restored)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 200 {
		t.Fatalf("download after restore: %d", rec.Code)
	}
}

func TestARevokedSourceLeavesTheOtherSourcesLinksAlone(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024", "public-share")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"sources":["photo/2024","public-share"],"name":"two"}`), &made)
	slugA := slugOf(t, made, "2024/a.jpg")
	slugIndex := slugOf(t, made, "public-share/index.html")
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["public-share"],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("narrow: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugA, "", ""); rec.Code != 404 {
		t.Fatalf("revoked entry: %d, want 404", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/download/"+made.ID+"/"+slugIndex, "", ""); rec.Code != 200 {
		t.Fatalf("the other source's link: %d, want 200 under the same prefixed slug", rec.Code)
	}
	var after revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, bob, ""), &after)
	if slugOf(t, after, "public-share/index.html") != slugIndex {
		t.Fatal("the surviving source was re-keyed")
	}
}

func TestDemotionRevokesAndPromotionRestores(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	if rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"carol","password":"pw-carol-secret","role":"admin","currentPassword":"`+testAdminPassword+`"}`); rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	carol, _ := login(t, h, "carol", "pw-carol-secret")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", carol, `{"source":"photo/2024"}`), &made)
	if rec := doReq(t, h, "PATCH", "/api/users/carol", testToken, `{"role":"user"}`); rec.Code != 409 {
		t.Fatalf("demotion without confirmation: %d", rec.Code)
	}
	if rec := doReq(t, h, "PATCH", "/api/users/carol", testToken, `{"role":"user","confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("demotion: %d %s", rec.Code, rec.Body)
	}
	var revoked revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, carol, ""), &revoked)
	if revoked.Linked["photo/2024"].Revoked == nil {
		t.Fatalf("demoted admin's share = %+v", revoked)
	}
	if rec := doReq(t, h, "PATCH", "/api/users/carol", testToken, `{"role":"admin","currentPassword":"`+testAdminPassword+`"}`); rec.Code != 200 {
		t.Fatalf("promotion: %d %s", rec.Code, rec.Body)
	}
	var restored revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+made.ID, carol, ""), &restored)
	if len(restored.Linked) != 0 || len(restored.Files) != 2 {
		t.Fatalf("promotion did not restore: %+v", restored)
	}
}

func TestAMissingRootDoesNotRevoke(t *testing.T) {
	// A handler with NO roots at all stands in for a NAS whose volume is
	// unmounted this minute: an unrelated edit must not revoke a thing.
	h, hd := newTestAPIParts(t)
	if rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"bob","password":"pw-bob-secret","quotaBytes":0,"sourceRoots":["photo/2024"]}`); rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	d, err := hd.db.CreateShare(metadb.CreateOptions{Owner: "bob", Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}
	bob, code := login(t, h, "bob", "pw-bob-secret")
	if code != 200 {
		t.Fatalf("login bob: %d", code)
	}
	// The list is SENT, so the revoke verdict runs, against a server with no
	// roots at all.
	rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["photo/2024"]}`)
	if rec.Code != 200 {
		t.Fatalf("an edit that keeps the list: %d %s", rec.Code, rec.Body)
	}
	var v revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+d.ID, bob, ""), &v)
	if len(v.Linked) != 0 {
		t.Fatalf("linked = %+v, want empty on a rootless server", v.Linked)
	}
}

func TestAHiddenGrantIsRefused(t *testing.T) {
	h := newTestAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken,
		`{"username":"bob","quotaBytes":0,"sourceRoots":["photo/#recycle"]}`)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad-source") {
		t.Fatalf("hidden grant: %d %s", rec.Code, rec.Body)
	}
}

func TestAnAdminSeesAndTouchesOnlyTheirOwnShares(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"bobs"}`), &made)
	var list struct {
		Shares []struct {
			ID    string  `json:"id"`
			Owner *string `json:"owner"`
		} `json:"shares"`
	}
	listRec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if listRec.Code != 200 {
		t.Fatalf("admin list = %d %s, want 200", listRec.Code, listRec.Body)
	}
	unmarshal(t, listRec, &list)
	for _, d := range list.Shares {
		if d.ID == made.ID {
			t.Fatal("the admin's list holds another account's share")
		}
		if d.Owner != nil {
			t.Fatal("owner travels on a share view")
		}
	}
	for _, probe := range []struct{ method, path, body string }{
		{"GET", "/api/shares/" + made.ID, ""},
		{"PATCH", "/api/shares/" + made.ID, `{"name":"taken"}`},
		{"DELETE", "/api/shares/" + made.ID, ""},
	} {
		if rec := doReq(t, h, probe.method, probe.path, testToken, probe.body); rec.Code != 404 {
			t.Fatalf("%s %s as admin = %d, want 404", probe.method, probe.path, rec.Code)
		}
	}
	var changes struct {
		Changes []struct {
			Share *struct{ ID string } `json:"share"`
		} `json:"changes"`
	}
	changesRec := doReq(t, h, "GET", "/api/shares/changes?since=0", testToken, "")
	if changesRec.Code != 200 {
		t.Fatalf("admin changes = %d %s, want 200", changesRec.Code, changesRec.Body)
	}
	unmarshal(t, changesRec, &changes)
	for _, c := range changes.Changes {
		if c.Share != nil && c.Share.ID == made.ID {
			t.Fatal("the admin's change feed carries another account's share")
		}
	}
}

// A bearer proves ownership of the share it belongs to, never another
// account's: putting the admin bypass back into bearerOwns would pass every
// other suite, so this drives it directly against both gates it used to
// cross, with the owner's own bearer as the control that the fixture is
// otherwise reachable.
func TestAnAdminsBearerUnlocksNoOtherAccountsDownload(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	bob := seedUser(t, um, "bob")

	var protected revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"name":"p","password":"hunter2"}`), &protected)
	if rec := doReq(t, h, "PUT", "/api/shares/"+protected.ID+"/files/a.txt", bob, "secret"); rec.Code != 201 {
		t.Fatalf("upload to protected share: %d %s", rec.Code, rec.Body)
	}
	var withFile revokedView
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+protected.ID, bob, ""), &withFile)
	pSlug := slugOf(t, withFile, "a.txt")

	var caught revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"name":"inbox","receive":true}`), &caught)
	if rec := doReq(t, h, "PUT", "/receive/"+caught.ID+"/files/received.txt", "", "sent"); rec.Code != 201 {
		t.Fatalf("inbox upload: %d %s", rec.Code, rec.Body)
	}
	unmarshal(t, doReq(t, h, "GET", "/api/shares/"+caught.ID, bob, ""), &caught)
	cSlug := slugOf(t, caught, "received.txt")

	protectedURL := "/download/" + protected.ID + "/" + pSlug
	inboxURL := "/download/" + caught.ID + "/" + cSlug

	// The admin's bearer is a stranger to both, so it gets exactly the
	// anonymous answer: the password form on the protected share, 404 on
	// the invisible inbox.
	anon := doReq(t, h, "GET", protectedURL, "", "")
	admin := doReq(t, h, "GET", protectedURL, testToken, "")
	if admin.Code != anon.Code || admin.Body.String() != anon.Body.String() {
		t.Fatalf("admin bearer on the protected share = %d %q, want the anonymous answer %d %q",
			admin.Code, admin.Body.String(), anon.Code, anon.Body.String())
	}
	if admin.Code != 200 || !strings.Contains(admin.Body.String(), "password") {
		t.Fatalf("anonymous/admin answer is not the password form: %d %q", admin.Code, admin.Body.String())
	}
	if rec := doReq(t, h, "GET", inboxURL, testToken, ""); rec.Code != 404 {
		t.Fatalf("admin bearer on another account's inbox = %d, want 404", rec.Code)
	}

	// Control: the owner's own bearer succeeds on both of the same URLs.
	if rec := doReq(t, h, "GET", protectedURL, bob, ""); rec.Code != 200 || rec.Body.String() != "secret" {
		t.Fatalf("owner bearer on the protected share = %d %q", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "GET", inboxURL, bob, ""); rec.Code != 200 || rec.Body.String() != "sent" {
		t.Fatalf("owner bearer on the inbox = %d %q", rec.Code, rec.Body.String())
	}
}

// Only an edit to the allowlist or the role decides a revoke. An account
// holding a linked share its list does not cover (a share made before the list
// existed, or imported) can still be suspended and have its password reset,
// and neither edit touches that share.
func TestAnEditLeavingTheAllowlistAloneRevokesNothing(t *testing.T) {
	h, b, _ := linkedTestAPI(t)
	grantedUser(t, h, "bob")
	d, err := b.DB.CreateShare(metadb.CreateOptions{Name: "old", Owner: "bob", Folder: true, Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"disabled":true}`, `{"resetPassword":true}`, `{"quotaBytes":5}`} {
		if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, body); rec.Code != 200 {
			t.Fatalf("%s: %d %s, want 200", body, rec.Code, rec.Body)
		}
	}
	shares, err := b.DB.LinkedSharesOf("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 1 || shares[0].ID != d.ID || len(shares[0].Sources) != 1 || shares[0].Sources[0].Revoked() {
		t.Fatalf("bob's linked shares = %+v, want %s's source untouched", shares, d.ID)
	}
	rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["public-share"]}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"revokes-shares"`) {
		t.Fatalf("an allowlist edit still decides the revoke: %d %s", rec.Code, rec.Body)
	}
}

// A linked entry's gallery tile and the share's poster answer exactly as the
// entry's own link does: dead while the entry is hidden or its source
// revoked, back on show and on restore, because the slug the tile is keyed
// by never left.
func TestALinkedTileAndPosterFollowHideRevokeAndRestore(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"trip"}`), &made)
	slugA := slugOf(t, made, "a.jpg")
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/thumbs/"+slugA, bob, string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("tile: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/poster", bob, string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("poster: %d %s", rec.Code, rec.Body)
	}
	tile := "/thumb/" + made.ID + "/" + slugA
	poster := "/card/" + made.ID + "/poster.jpg"
	want := func(step string, tileCode, posterCode int) {
		t.Helper()
		if rec := doReq(t, h, "GET", tile, "", ""); rec.Code != tileCode {
			t.Errorf("%s: tile = %d, want %d", step, rec.Code, tileCode)
		}
		if rec := doReq(t, h, "GET", poster, "", ""); rec.Code != posterCode {
			t.Errorf("%s: poster = %d, want %d", step, rec.Code, posterCode)
		}
	}
	want("published", 200, 200)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide: %d %s", rec.Code, rec.Body)
	}
	want("hidden", 404, 200)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"show":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("show: %d %s", rec.Code, rec.Body)
	}
	want("shown", 200, 200)
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":[],"confirmRevoke":true}`); rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	want("revoked", 404, 404)
	if rec := doReq(t, h, "PATCH", "/api/users/bob", testToken, `{"sourceRoots":["photo"]}`); rec.Code != 200 {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	want("restored", 200, 200)
}

// A poster set while a linked share shows one entry names that entry, so
// hiding it through the source's filter withholds the poster, as a revoke
// does, and showing it again brings the poster back.
func TestHidingThePostersLinkedEntryWithholdsThePoster(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	var made revokedView
	unmarshal(t, doReq(t, h, "POST", "/api/shares", bob, `{"source":"photo/2024","name":"trip"}`), &made)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"hide":["b.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide b: %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PUT", "/api/shares/"+made.ID+"/poster", bob, string(aJPEG(t, 8, 6))); rec.Code != 204 {
		t.Fatalf("poster: %d %s", rec.Code, rec.Body)
	}
	poster := "/card/" + made.ID + "/poster.jpg"
	want := func(step string, code int) {
		t.Helper()
		if rec := doReq(t, h, "GET", poster, "", ""); rec.Code != code {
			t.Errorf("%s: poster = %d, want %d", step, rec.Code, code)
		}
	}
	want("published", 200)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"hide":["a.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("hide a: %d %s", rec.Code, rec.Body)
	}
	want("its entry hidden", 404)
	if rec := doReq(t, h, "PATCH", "/api/shares/"+made.ID, bob, `{"linked":{"photo/2024":{"show":["a.jpg","b.jpg"]}}}`); rec.Code != 200 {
		t.Fatalf("show: %d %s", rec.Code, rec.Body)
	}
	want("shown again", 200)
}

// A narrowing and a share gaining a source can commit in either order, each
// admitted against the allowlist the other is replacing. Both halves look
// again after their own commit, so the source ends revoked whichever came
// first: the share's write finds the narrowed list (revokeUngranted), the
// narrowing finds the share (revokeLateSources).
func TestASourceAddedAcrossANarrowingEndsRevoked(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	h := hd.routes()
	grantedUser(t, h, "bob", "photo/2024")
	none := []string{}
	narrow := metadb.Settings{SourceRoots: &none}
	revoked := func(id string) bool {
		t.Helper()
		d, err := b.DB.Share(id)
		if err != nil {
			t.Fatal(err)
		}
		return len(d.Sources) == 1 && d.Sources[0].Revoked()
	}

	// The narrowing commits first, its flips computed before the share
	// existed; the share's own second look revokes the source.
	first, err := b.DB.CreateShare(metadb.CreateOptions{Name: "first", Owner: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DB.UpdateUserAccess("bob", narrow, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.DB.SetSources(first.ID, []string{"photo/2024"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := hd.revokeUngranted(first.ID, "bob", []string{"photo/2024"}); err != nil {
		t.Fatal(err)
	}
	if !revoked(first.ID) {
		t.Fatal("a source added after the narrowing committed serves unrevoked")
	}

	// The share commits first, after the narrowing's first pass read the
	// shares; the narrowing's second pass revokes it.
	second, err := b.DB.CreateShare(metadb.CreateOptions{Name: "second", Owner: "bob", Folder: true,
		Sources: []string{"photo/2024"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := hd.revokeLateSources("bob", narrow); err != nil {
		t.Fatal(err)
	}
	if !revoked(second.ID) {
		t.Fatal("a source the narrowing's first pass missed serves unrevoked")
	}
	if rec := doReq(t, h, "GET", "/share/"+second.ID, "", ""); !strings.Contains(rec.Body.String(), "not available on this server") {
		t.Fatalf("the revoked share's page: %d", rec.Code)
	}
}

// An account with an allowlist cannot tell a server folder it was not
// granted from one that does not exist: both answer the same 403, so a guess
// at a shared folder's name learns nothing the root list does not show it.
func TestAnUngrantedFolderAndAMissingOneAnswerAlike(t *testing.T) {
	h, _, _ := linkedTestAPI(t)
	bob := grantedUser(t, h, "bob", "photo/2024")
	granted := doReq(t, h, "GET", "/api/sources/browse?path=public-share", bob, "")
	missing := doReq(t, h, "GET", "/api/sources/browse?path=finance", bob, "")
	strip := func(s, name string) string { return strings.ReplaceAll(s, name, "X") }
	if granted.Code != 403 || missing.Code != 403 ||
		strip(granted.Body.String(), "public-share") != strip(missing.Body.String(), "finance") {
		t.Fatalf("ungranted %d %s, missing %d %s: want the same 403", granted.Code, granted.Body, missing.Code, missing.Body)
	}
}
