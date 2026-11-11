package api

import (
	"testing"

	"hyperdrop/server/internal/metadb"
)

// The rule, stated directly on hand-built records so it does not depend on
// what the host's mime table happens to know. What a real server sniffs
// varies by box, which is the reason the rule reads the name as well.
func TestGalleryRefusalGatesOnlyWhatWouldBeTiled(t *testing.T) {
	file := func(path, mime string) fileView {
		return fileView{File: metadb.File{Path: path, Mime: mime}}
	}
	for _, tc := range []struct {
		name  string
		files []fileView
		code  string
	}{
		{"photos a browser draws", []fileView{
			file("a.png", "image/png"), file("b.jpg", "image/jpeg")}, ""},
		{"a document beside them is listed, not tiled", []fileView{
			file("a.png", "image/png"), file("notes.pdf", "application/pdf")}, ""},
		{"an SVG is a document, whatever its type says", []fileView{
			file("a.png", "image/png"), file("logo.svg", "image/svg+xml")}, ""},
		{"a playable video", []fileView{file("clip.mp4", "video/mp4")}, ""},
		{"a container no browser plays", []fileView{
			file("clip.mov", "video/quicktime")}, "not-gallery-playable"},
		{"a HEIC the box knows", []fileView{
			file("IMG_1.heic", "image/heic")}, "not-gallery-playable"},
		// The box did not know the extension and sniffed the bytes as
		// nothing in particular. Read by MIME alone this is an ordinary file
		// and the gallery would list it; the name is what gives it away.
		{"a HEIC the box does not know", []fileView{
			file("IMG_1.heic", "application/octet-stream")}, "not-gallery-playable"},
		{"a MOV the box does not know", []fileView{
			file("clip.mov", "application/octet-stream")}, "not-gallery-playable"},
		// The mirror image: a name that says nothing, bytes that do.
		{"an extensionless photo", []fileView{file("IMG_1", "image/jpeg")}, ""},
		{"an extensionless raw", []fileView{file("IMG_1", "image/x-canon-cr2")},
			"not-gallery-playable"},
		{"nothing to show", nil, "no-pictures"},
		// A gallery with nothing to lay out is not a gallery.
		{"documents only", []fileView{file("notes.pdf", "application/pdf")},
			"no-pictures"},
		{"a web page only", []fileView{
			file("index.html", "text/html"), file("style.css", "text/css")}, "no-pictures"},
	} {
		err := galleryRefusal(shareView{Files: tc.files})
		if code := refusalCode(err); code != tc.code {
			t.Errorf("%s: code = %q (%v), want %q", tc.name, code, err, tc.code)
		}
	}
}

func TestGalleryRefusalWaitsForAnUploadToFinish(t *testing.T) {
	sh := shareView{Files: []fileView{
		{File: metadb.File{Path: "a.png", Mime: "image/png"}},
		{File: metadb.File{Path: "b.png", Pending: true}},
	}}
	if code := refusalCode(galleryRefusal(sh)); code != "share-incomplete" {
		t.Fatalf("code = %q, want share-incomplete", code)
	}
}

// refusalCode is the machine-readable code err answers with, "" for nil.
func refusalCode(err error) string {
	if err == nil {
		return ""
	}
	return refusalOf(err).code
}
