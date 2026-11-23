package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/metadb"
)

// What a browser actually receives for a big share. The page renders ONE
// folder, so its weight follows the folder's children and not the share:
// a node_modules-shaped share of n files over 100 top-level folders answers
// its root in 100 folder rows however large n grows, and a leaf folder in
// its own handful of rows. This measures both and pins the bound.
func TestListingPageWeightScales(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	for _, n := range []int{100, 1000, 5000, maxManifestFiles} {
		t.Run(fmt.Sprint(n, "-files"), func(t *testing.T) {
			h, _, b := newMultiUserAPI(t)
			type spec struct {
				Path string `json:"path"`
				Size int64  `json:"size"`
			}
			specs := make([]spec, n)
			for i := range specs {
				specs[i] = spec{Path: fmt.Sprintf("dir%03d/sub%02d/file%06d.bin", i%100, i%20, i), Size: int64(i * 1024)}
			}
			raw, err := json.Marshal(map[string]any{"name": "big", "folder": true, "files": specs})
			if err != nil {
				t.Fatal(err)
			}
			rec := doReq(t, h, "POST", "/api/shares", testToken, string(raw))
			if rec.Code != http.StatusCreated {
				t.Fatalf("create → %d: %.200s", rec.Code, rec.Body)
			}
			var out struct{ ID string }
			unmarshal(t, rec, &out)
			// The listing renders only once every file has landed (a share
			// still uploading is the waiting page), so commit each entry
			// straight into the database: the measurement is of the rows, and
			// the bytes behind them are not what it weighs. No bytes are
			// written, since staging and syncing 16,100 files is most of what
			// this test would otherwise spend.
			for _, f := range specs {
				if _, err := b.DB.CommitFile(metadb.CommitInput{ShareID: out.ID, Path: f.Path,
					Mime: "application/octet-stream"}); err != nil {
					t.Fatal(err)
				}
			}

			start := time.Now()
			page := doReq(t, h, "GET", "/share/"+out.ID, "", "")
			render := time.Since(start)
			if page.Code != http.StatusOK {
				t.Fatalf("root → %d", page.Code)
			}
			html := page.Body.String()
			if strings.Contains(html, "<script") {
				t.Error("a listing page must not contain JavaScript at any share size")
			}
			folders := strings.Count(html, `class="folder"`)
			rows := strings.Count(html, `class="row"`)
			t.Logf("%6d files: root HTML %7.2f KiB | render %8s | folders %d | rows %d",
				n, float64(len(html))/1024, render.Round(time.Millisecond), folders, rows)
			wantFolders := 100
			if n < 100 {
				wantFolders = n
			}
			if folders != wantFolders || rows != 0 {
				t.Errorf("root rendered %d folders and %d rows for %d files, want %d folders and no rows", folders, rows, n, wantFolders)
			}
			if len(html) > 64<<10 {
				t.Errorf("root page is %d bytes for %d files; one folder must not grow with the share", len(html), n)
			}

			leaf := doReq(t, h, "GET", "/share/"+out.ID+"?dir=dir000%2Fsub00", "", "")
			if leaf.Code != http.StatusOK {
				t.Fatalf("leaf → %d", leaf.Code)
			}
			lhtml := leaf.Body.String()
			lrows := strings.Count(lhtml, `class="row"`)
			// Files i with i%100==0 and i%20==0 land in dir000/sub00: every
			// multiple of 100.
			wantRows := (n + 99) / 100
			if lrows != wantRows || strings.Count(lhtml, `class="folder"`) != 0 {
				t.Errorf("leaf rendered %d rows for %d files, want %d and no folders", lrows, n, wantRows)
			}
			if !strings.Contains(lhtml, `class="crumbs"`) || !strings.Contains(lhtml, `?dir=dir000">dir000</a>`) {
				t.Errorf("leaf page lacks the breadcrumb trail back through dir000")
			}
		})
	}
}
