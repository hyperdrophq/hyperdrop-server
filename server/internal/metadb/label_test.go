package metadb

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// A label is shown to a person deciding whether to approve a device, in a
// prompt, a terminal and a push alarm, so it keeps nothing that can reorder or
// hide what is around it.
func TestALabelKeepsNoControlOrFormatCharacter(t *testing.T) {
	for in, want := range map[string]string{
		"Dmitry's iPhone":             "Dmitry's iPhone",
		"Dmi\u202etry\u200b\"x\"\x07": "Dmitry\"x\"",
		"a\nb\tc":                     "abc",
		"bad\xffutf8":                 "badutf8",
	} {
		if got := clampLabel(in); got != want {
			t.Errorf("clampLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := clampLabel(strings.Repeat("é", MaxLabelBytes)); len(got) > MaxLabelBytes {
		t.Errorf("kept %d bytes", len(got))
	}
}

// A public session ends 12 hours after its sign-in, a password change on the
// way included: the replacement session inherits the limit and does not move it.
func TestAPublicSessionKeepsItsLimitAcrossAPasswordChange(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("bob", "bob-password-1", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	signedIn := now.Add(-11 * time.Hour)
	if _, err := db.SetPasswordMintingWebSession("bob", "bob-password-2", "web", false, signedIn, now); err != nil {
		t.Fatal(err)
	}
	var expires int64
	if err := db.read(func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT expires_at FROM tokens WHERE username = 'bob' AND kind = ?`, TokenKindWeb).Scan(&expires)
	}); err != nil {
		t.Fatal(err)
	}
	if got, want := time.Unix(0, expires), signedIn.Add(WebAbsolute); got.Sub(want).Abs() > time.Second {
		t.Fatalf("expires %v, want %v", got, want)
	}
}
