package api

// A listing is bounded in SHARES and, until this, in nothing else: 500 rows
// over 20,000-file shares built ten million file entries for one response,
// about 4 GB, on a box whose whole memory limit is a fraction of that. These
// pin both ceilings and the honest reporting that makes truncation usable.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"hyperdrop/server/internal/metadb"
)

type listRow struct {
	ID             string `json:"id"`
	FileCount      int    `json:"fileCount"`
	FilesTruncated bool   `json:"filesTruncated"`
	TotalSize      int64  `json:"totalSize"`
	Files          []struct {
		Path string `json:"path"`
	} `json:"files"`
}

type listResp struct {
	Shares []listRow `json:"shares"`
	Total  int       `json:"total"`
	Offset int       `json:"offset"`
}

func getListing(t *testing.T, h http.Handler, query string) listResp {
	t.Helper()
	rec := doReq(t, h, "GET", "/api/shares"+query, testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing %q = %d: %s", query, rec.Code, rec.Body)
	}
	var out listResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding listing: %v", err)
	}
	return out
}

// addFiles commits n files straight through the backend: the HTTP upload
// path is exercised elsewhere and a round trip per file makes these tests
// slow.
func addFiles(t *testing.T, b Backend, id string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		commitFile(t, b, id, fmt.Sprintf("f%04d.txt", i), fmt.Sprintf("content %d", i))
	}
}

func TestListingCapsFilesPerShare(t *testing.T) {
	h, b := newTestAPIBackend(t)
	defer restoreListBounds(t)
	listMaxFilesPerShare = 10

	id := createShare(t, h, "fat")
	const n = 25
	addFiles(t, b, id, n)

	out := getListing(t, h, "")
	if len(out.Shares) != 1 {
		t.Fatalf("listing has %d shares, want 1", len(out.Shares))
	}
	row := out.Shares[0]
	if len(row.Files) != listMaxFilesPerShare {
		t.Errorf("row carries %d file entries, want the cap of %d",
			len(row.Files), listMaxFilesPerShare)
	}
	if !row.FilesTruncated {
		t.Error("a capped row must say so, or a client cannot know to fetch the rest")
	}
	// The counts describe the WHOLE share, not the window: a client showing
	// "25 files" must not be able to read the wrong number off a listing.
	if row.FileCount != n {
		t.Errorf("fileCount = %d, want %d", row.FileCount, n)
	}
	if row.TotalSize == 0 {
		t.Error("totalSize is 0 for a truncated row - it must sum every file")
	}
}

// A share inside the cap is untouched: the normal case pays nothing and
// reports no truncation.
func TestListingLeavesSmallSharesWhole(t *testing.T) {
	h, b := newTestAPIBackend(t)
	id := createShare(t, h, "small")
	addFiles(t, b, id, 3)

	row := getListing(t, h, "").Shares[0]
	if len(row.Files) != 3 || row.FilesTruncated || row.FileCount != 3 {
		t.Errorf("small share: %d files, truncated=%v, fileCount=%d; want 3/false/3",
			len(row.Files), row.FilesTruncated, row.FileCount)
	}
}

// The single-share read is never capped. That is what makes truncation
// recoverable: a client meeting filesTruncated fetches the whole record.
func TestSingleShareReadIsNeverCapped(t *testing.T) {
	h, b := newTestAPIBackend(t)
	defer restoreListBounds(t)
	listMaxFilesPerShare = 10

	id := createShare(t, h, "fat")
	const n = 25
	addFiles(t, b, id, n)

	rec := doReq(t, h, "GET", "/api/shares/"+id, testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET share = %d: %s", rec.Code, rec.Body)
	}
	var row listRow
	if err := json.Unmarshal(rec.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if len(row.Files) != n || row.FilesTruncated {
		t.Errorf("single-share read gave %d files (truncated=%v), want all %d",
			len(row.Files), row.FilesTruncated, n)
	}
	if row.FileCount != n {
		t.Errorf("fileCount = %d, want %d", row.FileCount, n)
	}
}

// The per-share cap alone does not bound a page: the max row limit times the
// cap is still hundreds of thousands of entries. The page budget stops many
// medium shares too, by spending itself across the rows: once it is gone a
// row carries no file entries at all and says so, while still reporting the
// share's real size.
func TestListingBudgetsFilesAcrossThePage(t *testing.T) {
	h, b := newTestAPIBackend(t)
	defer restoreListBounds(t)
	listMaxFilesPerPage = 50

	// Four shares of 30 files each against a budget of 50.
	for i := 0; i < 4; i++ {
		id := createShare(t, h, fmt.Sprintf("s%d", i))
		addFiles(t, b, id, 30)
	}

	out := getListing(t, h, "")
	if out.Total != 4 {
		t.Errorf("total = %d, want 4 - the budget bounds the FILES, not the count", out.Total)
	}
	entries := 0
	for _, row := range out.Shares {
		entries += len(row.Files)
		if row.FileCount != 30 {
			t.Errorf("row %s reports %d files, want the share's real 30", row.ID, row.FileCount)
		}
		if row.FilesTruncated == (len(row.Files) == 30) {
			t.Errorf("row %s carries %d entries and says truncated=%v",
				row.ID, len(row.Files), row.FilesTruncated)
		}
	}
	if entries > listMaxFilesPerPage {
		t.Errorf("the page carries %d file entries, over the budget of %d",
			entries, listMaxFilesPerPage)
	}
	// Paging still reaches everything: offset picks up where the page stopped.
	next := getListing(t, h, "?offset=2")
	if len(next.Shares) == 0 {
		t.Error("the shares past the budget are unreachable by paging")
	}
}

// A single share bigger than the whole page budget must still be returned,
// or a listing that begins with one comes back empty and nothing can page
// past it.
func TestAShareBiggerThanTheBudgetStillAppears(t *testing.T) {
	h, b := newTestAPIBackend(t)
	defer restoreListBounds(t)
	listMaxFilesPerPage = 5

	id := createShare(t, h, "enormous")
	addFiles(t, b, id, 30)

	out := getListing(t, h, "")
	if len(out.Shares) != 1 || out.Shares[0].ID != id {
		t.Fatalf("page has %d shares, want the one share that exceeds the budget", len(out.Shares))
	}
}

func restoreListBounds(t *testing.T) {
	t.Helper()
	listMaxFilesPerShare, listMaxFilesPerPage = metadb.DefaultMaxFilesPerShare, metadb.DefaultMaxFilesPerPage
}
