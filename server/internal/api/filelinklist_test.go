package api

import (
	"testing"
)

// A listing page answers each file's key: the keyed share's file carries its
// key and an unkeyed share's file carries none.
func TestAListingPageAnswersEachFilesKey(t *testing.T) {
	h, _ := newTestAPIWithUsers(t)
	var keyed string
	for i := 0; i < 6; i++ {
		id := createShare(t, h, "s")
		uploadFile(t, h, testToken, id, "a.txt", "A")
		if keyed == "" {
			keyed = id
			slug := getFileLinkShare(t, h, testToken, id).Files[0].Slug
			mintFileKey(t, h, testToken, id, slug)
		}
	}
	if got := getFileLinkShare(t, h, testToken, keyed); got.Files[0].FileKey == "" {
		t.Fatal("the keyed share's own answer lost its key")
	}
	rec := doReq(t, h, "GET", "/api/shares", testToken, "")
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var listing struct {
		Shares []fileLinkShare `json:"shares"`
	}
	unmarshal(t, rec, &listing)
	found := false
	for _, s := range listing.Shares {
		if s.ID == keyed {
			found = true
			if len(s.Files) != 1 || s.Files[0].FileKey == "" {
				t.Fatalf("the listing dropped the key: %+v", s.Files)
			}
		} else if len(s.Files) == 1 && s.Files[0].FileKey != "" {
			t.Fatalf("an unkeyed share carries a key: %+v", s.Files)
		}
	}
	if !found {
		t.Fatal("the keyed share is not listed")
	}
}
