package api

import (
	"net/http"
	"strings"
	"testing"
)

const commonRefusal = `{"error":"this password is too common, choose another"}`

func TestEveryChosenPasswordRouteRefusesACommonOne(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "alice")
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/users", `{"username":"carol","password":"password1","role":"admin"}`},
		{"PATCH", "/api/users/alice", `{"password":"password1"}`},
		{"PATCH", "/api/me/password", `{"password":"password1","currentPassword":"` + testAdminPassword + `"}`},
	} {
		rec := doReq(t, h, tc.method, tc.path, testToken, tc.body)
		if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != commonRefusal {
			t.Errorf("%s %s = %d %s, want 400 %s", tc.method, tc.path, rec.Code, rec.Body, commonRefusal)
		}
	}
	if _, err := db.User("carol"); err == nil {
		t.Fatal("a refused create made the account")
	}
	if rec := tryLogin(t, h, "alice", "alice-pw", ""); rec.Code != http.StatusOK {
		t.Fatalf("alice's old password after a refused edit = %d %s", rec.Code, rec.Body)
	}
	if rec := tryLogin(t, h, "admin", testAdminPassword, ""); rec.Code != http.StatusOK {
		t.Fatalf("the admin's old password after a refused change = %d %s", rec.Code, rec.Body)
	}
}

func TestACommonNewPasswordSpendsNoCode(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	secret, _ := enableTOTP(t, h, testToken, testAdminPassword)
	code := nextCode(t, secret)
	rec := doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"password":"password1","currentPassword":"`+testAdminPassword+`","totp":"`+code+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a common password with a valid code = %d %s, want 400", rec.Code, rec.Body)
	}
	rec = doReq(t, h, "PATCH", "/api/me/password", testToken,
		`{"password":"a-strong-one-7","currentPassword":"`+testAdminPassword+`","totp":"`+code+`","signOutOthers":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("the same code after the refusal = %d %s, want 200", rec.Code, rec.Body)
	}
}

func TestAnExistingCommonPasswordStillWorks(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	seedUser(t, db, "alice")
	if err := db.SetPassword("alice", "password1"); err != nil {
		t.Fatal(err)
	}
	rec := tryLogin(t, h, "alice", "password1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login with a common password already set = %d %s", rec.Code, rec.Body)
	}
	var out struct{ Token string }
	unmarshal(t, rec, &out)
	if rec := doReq(t, h, "POST", "/api/me/totp", out.Token, `{"currentPassword":"password1"}`); rec.Code != http.StatusOK {
		t.Fatalf("a step-up with it = %d %s", rec.Code, rec.Body)
	}
	if rec := doReq(t, h, "PATCH", "/api/me/password", out.Token,
		`{"password":"a-strong-one-7","currentPassword":"password1"}`); rec.Code != http.StatusOK {
		t.Fatalf("changing it to a strong one = %d %s", rec.Code, rec.Body)
	}
}

func TestAGeneratedPasswordIsNeverRefused(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	rec := doReq(t, h, "POST", "/api/users", testToken, `{"username":"dave","role":"user","quotaBytes":0}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create without a password = %d %s, want 201", rec.Code, rec.Body)
	}
}
