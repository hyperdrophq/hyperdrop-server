package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// splitLinkedHandler is splitHandler over the linked fixture volume.
func splitLinkedHandler(t *testing.T) (*handler, http.Handler, string) {
	t.Helper()
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dom, err := domain.Load(filepath.Join(t.TempDir(), "domain"), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := dom.Adopt(hopApp); err != nil {
		t.Fatal(err)
	}
	hh := newHandler(testBackendWithRoots(t, roots), "2.0.0", dom, nil, Deployment{})
	return hh, hh.routes(), vol
}

// The unavailable page of a protected linked share names the share only to
// a visitor holding that share's access, like its link card: the access hop
// answers it before any password is checked.
func TestProtectedLinkedShareUnavailablePageHidesTheName(t *testing.T) {
	const name = "Quarterly Ledger"
	hh, h, vol := splitLinkedHandler(t)
	share := func(password string) string {
		t.Helper()
		d, err := hh.db.CreateShare(metadb.CreateOptions{Name: name, Owner: metadb.DefaultAdminName,
			Folder: true, Sources: []string{"photo/2024"}, PasswordHash: password})
		if err != nil {
			t.Fatal(err)
		}
		return d.ID
	}
	protected, open := share("$2a$04$not-checked-on-this-route"), share("")
	if err := os.RemoveAll(filepath.Join(vol, "photo")); err != nil {
		t.Fatal(err)
	}

	page := func(id string, cookies ...*http.Cookie) string {
		t.Helper()
		rec := browse(t, h, "GET", hopFile, "/access/"+id, "", cookies...)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not available on this server") {
			t.Fatalf("access hop of %s = %d %.200s, want the unavailable page", id, rec.Code, rec.Body)
		}
		return rec.Body.String()
	}

	body := page(protected)
	if strings.Contains(body, name) {
		t.Errorf("a visitor without access sees the protected share's name: %.400s", body)
	}
	if !strings.Contains(body, "<title>This share is unavailable</title>") {
		t.Errorf("title of the protected page: %.400s", body)
	}

	v, err := hh.viewMeta(protected)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: hh.cookieName(protected), Value: hh.signAccess(protected, v.PasswordGen, time.Now().Add(time.Hour), false)}
	if body := page(protected, cookie); !strings.Contains(body, "<title>"+name+"</title>") {
		t.Errorf("a visitor holding the share's access does not see its name: %.400s", body)
	}

	if body := page(open); !strings.Contains(body, "<title>"+name+"</title>") {
		t.Errorf("an unprotected share's page lost its name: %.400s", body)
	}
}
