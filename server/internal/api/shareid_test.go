package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Go's ServeMux percent-decodes a `{id}` wildcard AFTER matching, so a route
// that believes it holds one path segment can be handed a slash or a dot
// segment. These are the end-to-end forms of that.

func TestPublicRoutesRejectAnEncodedSlashInTheShareID(t *testing.T) {
	h := newTestAPI(t)
	id := createShare(t, h, "mine")
	for _, path := range []string{
		"/share/" + id + "%2Ffiles",
		"/zip/" + id + "%2Ffiles",
		"/share/..%2F..%2Fetc",
		"/share/" + id + "%2Ffiles/status",
	} {
		rec := doReq(t, h, "GET", path, "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

// The full attack: plant a file named like a share record inside your own
// share, naming somebody else's share, then address `<yours>/files` as if it
// were a share. Downstream, setAccessCookie mints from the share record's
// OWN id, so a forged record would yield a server-signed cookie unlocking
// the victim's password-protected share.
func TestForgedMetaCannotMintAnotherSharesAccessCookie(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	mallory := seedUser(t, um, "mallory")

	victimHash, err := bcrypt.GenerateFromPassword([]byte("victim-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	victim := createShareAs(t, h, testToken,
		fmt.Sprintf(`{"name":"victim","password":%q}`, "victim-secret"))

	mine := createShareAs(t, h, mallory, `{"name":"mine"}`)
	forged := fmt.Sprintf(
		`{"id":%q,"name":"pwned","owner":"mallory","passwordGen":0,"passwordHash":%q}`,
		victim, string(victimHash))
	rec := doReq(t, h, "PUT", "/api/shares/"+mine+"/files/meta.json", mallory, forged)
	if rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("upload forged meta: %d %s", rec.Code, rec.Body)
	}

	// Addressing the planted meta must 404, and must therefore hand out no
	// cookie at all.
	rec = doReq(t, h, "GET", "/share/"+mine+"%2Ffiles?pw=victim-secret", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET forged share = %d, want 404", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, "hd_") {
			t.Fatalf("forged share minted an access cookie %q", c.Name)
		}
	}

	// And the victim's share is still gated.
	rec = doReq(t, h, "GET", "/share/"+victim, "", "")
	if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "password") {
		t.Errorf("victim share served without its password form: %d", rec.Code)
	}
}

// The same planted record reached through an authenticated mutation: a write
// that trusted the ID the FILE claimed would overwrite the victim's record,
// stripping its password and transferring ownership.
func TestForgedMetaCannotOverwriteAnotherShare(t *testing.T) {
	h, um, st := newMultiUserAPI(t)
	mallory := seedUser(t, um, "mallory")
	victim := createShareAs(t, h, testToken, `{"name":"victim","password":"victim-secret"}`)
	mine := createShareAs(t, h, mallory, `{"name":"mine"}`)

	forged := fmt.Sprintf(`{"id":%q,"name":"pwned","owner":"mallory"}`, victim)
	if rec := doReq(t, h, "PUT", "/api/shares/"+mine+"/files/meta.json", mallory, forged); rec.Code != 201 && rec.Code != 200 {
		t.Fatalf("upload forged meta: %d %s", rec.Code, rec.Body)
	}

	rec := doReq(t, h, "PATCH", "/api/shares/"+mine+"%2Ffiles", mallory, `{"removePassword":true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PATCH forged share = %d, want 404", rec.Code)
	}

	sh, err := st.DB.Share(victim)
	if err != nil {
		t.Fatalf("victim share gone: %v", err)
	}
	if sh.Name != "victim" || sh.Owner != "admin" || sh.PasswordHash == "" {
		t.Errorf("victim share was modified: name=%q owner=%q hasPassword=%v",
			sh.Name, sh.Owner, sh.PasswordHash != "")
	}
}
