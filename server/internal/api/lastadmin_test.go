package api

import (
	"net/http"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// Two admins expiring each other each pass the self-target rule; the
// second edit is refused 409 last-admin, and a delete that would leave no
// lasting admin is refused before it removes the account's shares.
func TestTwoAdminsCannotLeaveTheServerWithoutOne(t *testing.T) {
	h, db, _ := newMultiUserAPI(t)
	if _, err := db.CreateUser("boris", "boris-password", metadb.RoleAdmin, metadb.Settings{}); err != nil {
		t.Fatal(err)
	}
	confirmTOTPInStore(t, db, "boris")
	boris, err := db.MintToken("boris", "test")
	if err != nil {
		t.Fatal(err)
	}
	later := `{"accountExpiresAt":"` + time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339) + `"}`
	if rec := doReq(t, h, "PATCH", "/api/users/boris", testToken, later); rec.Code != http.StatusOK {
		t.Fatalf("expiring the other admin = %d %s", rec.Code, rec.Body)
	}
	rec := doReq(t, h, "PATCH", "/api/users/admin", boris, later)
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "last-admin" {
		t.Fatalf("expiring the last lasting admin = %d %s, want 409 last-admin", rec.Code, rec.Body)
	}
	id := createShare(t, h, "kept")
	rec = doReq(t, h, "DELETE", "/api/users/admin", boris, "")
	if rec.Code != http.StatusConflict || errCode(t, rec.Body.String()) != "last-admin" {
		t.Fatalf("deleting the last lasting admin = %d %s, want 409 last-admin", rec.Code, rec.Body)
	}
	if _, err := db.Share(id); err != nil {
		t.Fatalf("the refused delete removed the account's share: %v", err)
	}
}
