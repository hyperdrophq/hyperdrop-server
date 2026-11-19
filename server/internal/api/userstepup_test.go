package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

func stepUpBody(t *testing.T, fields map[string]any) string {
	t.Helper()
	fields["currentPassword"] = testAdminPassword
	fields["totp"] = seededAdminCode(t)
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func wantUserStepUpRefusal(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != http.StatusForbidden || errCode(t, body) != "step-up-required" {
		t.Fatalf("%s = %d %s, want 403 step-up-required", what, code, body)
	}
}

// A stolen device token holds no password, so it cannot make an account that
// outlives its revoking.
func TestCreatingAnyAccountTakesTheCallersStepUp(t *testing.T) {
	h, b := newTestAPIBackend(t)
	const bare = `{"username":"mallory","password":"Correct-Horse-Battery-9","quotaBytes":0}`
	rec := doReqBare(t, h, "POST", "/api/users", testToken, bare)
	wantUserStepUpRefusal(t, "bare", rec.Code, rec.Body.String())
	if _, err := b.DB.User("mallory"); err == nil {
		t.Fatal("the account was created")
	}
	rec = doReqBare(t, h, "POST", "/api/users", testToken, stepUpBody(t, map[string]any{
		"username": "mallory", "password": "Correct-Horse-Battery-9", "quotaBytes": 0}))
	if rec.Code != 201 {
		t.Fatalf("with the step-up = %d %s", rec.Code, rec.Body)
	}
}

// A name the server would refuse is refused before the caller's code is spent,
// so the client does not have to ask for another.
func TestABadOrTakenNameSpendsNoCode(t *testing.T) {
	h, b := newTestAPIBackend(t)
	seedUser(t, b.DB, "bob")
	for _, name := range []string{"not a name!", "bob"} {
		body, _ := json.Marshal(map[string]any{"username": name, "quotaBytes": 0})
		rec := doReqBare(t, h, "POST", "/api/users", testToken, string(body))
		if rec.Code == http.StatusForbidden {
			t.Fatalf("%q asked for the step-up first: %s", name, rec.Body)
		}
		if rec.Code < 400 {
			t.Fatalf("%q = %d %s", name, rec.Code, rec.Body)
		}
	}
}

// Deleting an account takes its shares with it, and nothing brings them back.
func TestDeletingAnAccountTakesTheCallersStepUp(t *testing.T) {
	h, b := newTestAPIBackend(t)
	seedUser(t, b.DB, "bob")
	rec := doReqBare(t, h, "DELETE", "/api/users/bob", testToken, "")
	wantUserStepUpRefusal(t, "bare", rec.Code, rec.Body.String())
	if _, err := b.DB.User("bob"); err != nil {
		t.Fatalf("the account went anyway: %v", err)
	}
	rec = doReqBare(t, h, "DELETE", "/api/users/bob", testToken, stepUpBody(t, map[string]any{}))
	if rec.Code != 204 {
		t.Fatalf("with the step-up = %d %s", rec.Code, rec.Body)
	}
}

// Refusals nothing can answer come before the step-up, so no code is spent on
// them.
func TestADeleteRefusedAnywayAsksForNothing(t *testing.T) {
	h, _ := newTestAPIBackend(t)
	rec := doReqBare(t, h, "DELETE", "/api/users/nobody", testToken, "")
	if rec.Code != 404 {
		t.Fatalf("unknown account = %d %s", rec.Code, rec.Body)
	}
	rec = doReqBare(t, h, "DELETE", "/api/users/"+metadb.DefaultAdminName, testToken, "")
	if rec.Code != 403 || errCode(t, rec.Body.String()) != "self-target" {
		t.Fatalf("own account = %d %s", rec.Code, rec.Body)
	}
}

// Server folders are the one thing an account's edit can open that a quota does
// not bound. Giving them takes the step-up; taking them away does not, since a
// thief gains nothing by it and a person cleaning up must be able to.
func TestWideningServerFoldersTakesTheCallersStepUp(t *testing.T) {
	vol := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vol, "media", "a", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	h := New(b, "test", testDomain(t), nil)
	seedUser(t, b.DB, "bob")
	withRoots := func(list ...string) *[]string { return &list }
	if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: withRoots("media/a")}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
		asks bool
	}{
		{"a sibling", `{"sourceRoots":["media/a","media/b"]}`, true},
		{"the parent", `{"sourceRoots":["media"]}`, true},
		{"the same list", `{"sourceRoots":["media/a"]}`, false},
		{"below what it has", `{"sourceRoots":["media/a/sub"],"confirmRevoke":true}`, false},
		{"nothing", `{"sourceRoots":[],"confirmRevoke":true}`, false},
		{"another setting", `{"noEmbed":true}`, false},
	} {
		if _, err := b.DB.UpdateUser("bob", metadb.Settings{SourceRoots: withRoots("media/a")}); err != nil {
			t.Fatal(err)
		}
		rec := doReqBare(t, h, "PATCH", "/api/users/bob", testToken, tc.body)
		if tc.asks {
			wantUserStepUpRefusal(t, tc.name, rec.Code, rec.Body.String())
			continue
		}
		if rec.Code != 200 {
			t.Errorf("%s = %d %s, want it applied without a step-up", tc.name, rec.Code, rec.Body)
		}
	}
	rec := doReqBare(t, h, "PATCH", "/api/users/bob", testToken, stepUpBody(t, map[string]any{"sourceRoots": []string{"media"}}))
	if rec.Code != 200 {
		t.Fatalf("with the step-up = %d %s", rec.Code, rec.Body)
	}
}
