package metadb

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// A label past MaxLabelBytes is cut at a character boundary, on a login's
// token and on a phone's claim alike.
func TestALongDeviceLabelIsCut(t *testing.T) {
	db := openTest(t)
	if _, err := db.CreateUser("guest", "guest-password", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("é", 40<<10)
	if _, err := db.MintToken("guest", long); err != nil {
		t.Fatal(err)
	}
	u, err := db.User("guest")
	if err != nil {
		t.Fatal(err)
	}
	got := u.Tokens[0].Label
	if len(got) > MaxLabelBytes || !utf8.ValidString(got) || !strings.HasPrefix(long, got) || len(got) < MaxLabelBytes-1 {
		t.Fatalf("label of %d bytes, valid %v: want at most %d bytes, cut at a character", len(got), utf8.ValidString(got), MaxLabelBytes)
	}
}

// Past MaxTokensPerAccount a mint signs out the least recently used devices
// and never the one it just signed in.
func TestAMintPastTheCapSignsOutTheLeastRecentlyUsed(t *testing.T) {
	db := openTest(t)
	old := MaxTokensPerAccount
	MaxTokensPerAccount = 5
	t.Cleanup(func() { MaxTokensPerAccount = old })
	if _, err := db.CreateUser("guest", "guest-password", RoleUser, Settings{}); err != nil {
		t.Fatal(err)
	}
	var raws []string
	for i := range 5 {
		raw, err := db.MintTokenCreatedAt("guest", "d", at.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	// The oldest sign-in is the one in use, so the second oldest is the
	// least recently used.
	if _, err := db.UserByToken(raws[0], ClientInfo{}); err != nil {
		t.Fatal(err)
	}
	newest, err := db.MintToken("guest", "new")
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.User("guest")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Tokens) != MaxTokensPerAccount {
		t.Fatalf("%d tokens after a mint past the cap, want %d", len(u.Tokens), MaxTokensPerAccount)
	}
	for _, raw := range []string{raws[0], newest} {
		if _, err := db.UserByToken(raw, ClientInfo{}); err != nil {
			t.Fatalf("a token the trim must keep was signed out: %v", err)
		}
	}
	if _, err := db.UserByToken(raws[1], ClientInfo{}); err == nil {
		t.Fatal("the least recently used token survived the trim")
	}
}

// The trim never signs out a token that signed in a computer by phone or a
// web session (via_token): deleting it would detach them from the cascade
// that revokes them with it. It signs out the next least recently used
// token instead. A token that only linked a phone is trimmed as any other.
func TestTheTrimKeepsATokenWithPhoneOrWebDependents(t *testing.T) {
	for _, dep := range []struct {
		name, set string
	}{
		{"phone", `sign_in_method = 'phone'`},
		{"web", `kind = 'web'`},
	} {
		t.Run(dep.name, func(t *testing.T) {
			db := openTest(t)
			old := MaxTokensPerAccount
			MaxTokensPerAccount = 4
			t.Cleanup(func() { MaxTokensPerAccount = old })
			if _, err := db.CreateUser("guest", "guest-password", RoleUser, Settings{}); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for i := range 4 {
				raw, err := db.MintTokenCreatedAt("guest", "d", at.Add(time.Duration(i)*time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, tokenOf(t, db, "guest", TokenHash(raw)).ID)
			}
			// The least recently used token approved the newest one.
			if err := db.write(func(tx *sql.Tx) error {
				_, err := tx.Exec(`UPDATE tokens SET via_token = ?, `+dep.set+` WHERE id = ?`, ids[0], ids[3])
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.MintToken("guest", "new"); err != nil {
				t.Fatal(err)
			}
			left := tokenIDs(t, db, "guest")
			if len(left) != MaxTokensPerAccount || !slices.Contains(left, ids[0]) || !slices.Contains(left, ids[3]) || slices.Contains(left, ids[1]) {
				t.Fatalf("left %v of %v: want the approver and its dependent kept and the next oldest signed out", left, ids)
			}
		})
	}
	t.Run("linked phone", func(t *testing.T) {
		db := openTest(t)
		old := MaxTokensPerAccount
		MaxTokensPerAccount = 4
		t.Cleanup(func() { MaxTokensPerAccount = old })
		if _, err := db.CreateUser("guest", "guest-password", RoleUser, Settings{}); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for i := range 4 {
			raw, err := db.MintTokenCreatedAt("guest", "d", at.Add(time.Duration(i)*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, tokenOf(t, db, "guest", TokenHash(raw)).ID)
		}
		if err := db.write(func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE tokens SET via_token = ? WHERE id = ?`, ids[0], ids[3])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.MintToken("guest", "new"); err != nil {
			t.Fatal(err)
		}
		if left := tokenIDs(t, db, "guest"); slices.Contains(left, ids[0]) {
			t.Fatalf("left %v: the token that only linked a phone was kept", left)
		}
	})
}

// Every authenticated request reads the account's tokens in order, which
// the tokens_user index serves without scanning the table or sorting.
func TestAnAccountsTokensAreReadThroughAnIndex(t *testing.T) {
	db := openTest(t)
	err := db.read(func(tx *sql.Tx) error {
		rows, err := tx.Query(`EXPLAIN QUERY PLAN SELECT id FROM tokens WHERE username = ? ORDER BY created_at, id`, "guest")
		if err != nil {
			return err
		}
		defer rows.Close()
		var plan []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				return err
			}
			plan = append(plan, detail)
		}
		joined := strings.Join(plan, "; ")
		if !strings.Contains(joined, "tokens_user") || strings.Contains(joined, "TEMP B-TREE") {
			t.Fatalf("plan = %s, want the tokens_user index and no sort", joined)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}
