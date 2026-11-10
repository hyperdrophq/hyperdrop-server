package api

import (
	"testing"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// A source's filter that cannot be read serves nothing rather than the
// unfiltered folder: the listing is the unavailable one and no entry
// opens, so a file the owner hid is never listed or served for want of the
// list that hides it.
func TestAFailedFilterReadServesNothingHidden(t *testing.T) {
	vol := seedLinkedVolume(t)
	roots, err := linked.NewRoots(nil, []string{vol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := testBackendWithRoots(t, roots)
	hd := newHandler(b, "2.0.0", testDomain(t), nil, Deployment{})
	id := linkedShare(t, b, "photo/2024")
	if _, err := b.DB.EditFilter(id, []metadb.FilterEdit{{Source: "photo/2024", Hide: []string{"a.jpg"}}}); err != nil {
		t.Fatal(err)
	}
	d, err := b.DB.Share(id)
	if err != nil {
		t.Fatal(err)
	}
	// Every read from here fails, the filter read included.
	b.DB.Close()

	if _, err := hd.dbSpecs(d); err == nil {
		t.Fatal("dbSpecs answered specs without the filter it could not read")
	}
	v := shareView{Share: d}
	hd.linkedView(d, &v, false)
	if !v.SourceMissing || len(v.Files) != 0 {
		t.Fatalf("listing %+v (missing %v): want the unavailable listing", v.Files, v.SourceMissing)
	}
	o := hd.entryOpener(shareView{Share: d})
	defer o.Close()
	if f, _, _, err := o.open(fileView{Linked: true, File: metadb.File{Path: "a.jpg"}}); err == nil {
		f.Close()
		t.Fatal("the hidden entry opened")
	}
	if hd.listedCount(d, "photo/2024") != nil {
		t.Fatal("the revoke count read the folder without its filter")
	}
}
