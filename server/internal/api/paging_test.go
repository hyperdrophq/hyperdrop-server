package api

import (
	"net/http"
	"testing"
)

type pagedListing struct {
	Shares []struct {
		ID    string  `json:"id"`
		Name  string  `json:"name"`
		Owner *string `json:"owner"`
	} `json:"shares"`
	Total      int   `json:"total"`
	Offset     int   `json:"offset"`
	TotalBytes int64 `json:"totalBytes"`
}

func listPage(t *testing.T, h http.Handler, token, params string) pagedListing {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares"+params, token, "")
	if rec.Code != 200 {
		t.Fatalf("list%s: %d %s", params, rec.Code, rec.Body)
	}
	var out pagedListing
	unmarshal(t, rec, &out)
	return out
}

func TestListSharesPaginates(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	ids := map[string]bool{}
	for i := 0; i < 7; i++ {
		ids[createShareAs(t, h, testToken, `{"name":"page-test"}`)] = true
	}

	seen := map[string]bool{}
	for offset := 0; ; {
		page := listPage(t, h, testToken, "?offset="+itoa(offset)+"&limit=3")
		if page.Total != 7 {
			t.Fatalf("total = %d, want 7", page.Total)
		}
		if page.Offset != offset {
			t.Fatalf("offset echoed %d, want %d", page.Offset, offset)
		}
		for _, sh := range page.Shares {
			if seen[sh.ID] {
				t.Fatalf("share %s appeared on two pages", sh.ID)
			}
			seen[sh.ID] = true
		}
		offset += len(page.Shares)
		if len(page.Shares) == 0 || offset >= page.Total {
			break
		}
	}
	if len(seen) != 7 {
		t.Fatalf("pages yielded %d shares, want all 7", len(seen))
	}
	for id := range ids {
		if !seen[id] {
			t.Fatalf("share %s missing from the paged union", id)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestListSharesNameFilter(t *testing.T) {
	h, _, _ := newMultiUserAPI(t)
	createShareAs(t, h, testToken, `{"name":"Garden Plans"}`)
	createShareAs(t, h, testToken, `{"name":"taxes"}`)

	page := listPage(t, h, testToken, "?q=garden")
	if page.Total != 1 || len(page.Shares) != 1 || page.Shares[0].Name != "Garden Plans" {
		t.Fatalf("q=garden: total %d, %d rows", page.Total, len(page.Shares))
	}
	// The filter narrows total (that is what tells a client how many pages
	// the SEARCH has), but not the account byte figure.
	if all := listPage(t, h, testToken, ""); all.Total != 2 {
		t.Fatalf("unfiltered total = %d, want 2", all.Total)
	}
}

func TestListSharesScopedTotals(t *testing.T) {
	h, um, _ := newMultiUserAPI(t)
	alice := seedUser(t, um, "alice")
	bob := seedUser(t, um, "bob")
	aliceID := createShareAs(t, h, alice, `{"name":"alices"}`)
	createShareAs(t, h, bob, `{"name":"bobs"}`)
	if rec := doReq(t, h, "PUT", "/api/shares/"+aliceID+"/files/a.txt", alice, "hello"); rec.Code != 201 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}

	// A user's page: own shares only, own bytes only, total counts own.
	page := listPage(t, h, alice, "?limit=1")
	if page.Total != 1 || page.TotalBytes != 5 {
		t.Fatalf("alice: total %d, totalBytes %d; want 1, 5", page.Total, page.TotalBytes)
	}
	// An admin's page is scoped the same way: neither alice's nor bob's
	// shares or bytes count toward it until the admin makes its own.
	page = listPage(t, h, testToken, "")
	if page.Total != 0 || page.TotalBytes != 0 {
		t.Fatalf("admin: total %d, totalBytes %d; want 0, 0", page.Total, page.TotalBytes)
	}
	for _, sh := range page.Shares {
		if sh.Owner != nil {
			t.Fatalf("owner travels on a share view: %+v", sh)
		}
	}
}
