package mimetype

import (
	"bytes"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestViewable(t *testing.T) {
	cases := []struct {
		mime string
		want bool
	}{
		{"image/png", true},
		{"video/mp4", true},
		{"audio/mpeg", true},
		{"text/plain; charset=utf-8", true},
		{"text/html; charset=utf-8", true},
		{"application/pdf", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/rss+xml", true},
		{"application/geo+json", true},
		{"application/octet-stream", false},
		{"application/x-apple-diskimage", false},
		{"application/zip", false},
		{"application/vnd.microsoft.portable-executable", false},
		{"", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		if got := Viewable(tc.mime); got != tc.want {
			t.Errorf("Viewable(%q) = %v, want %v", tc.mime, got, tc.want)
		}
	}
}

func TestDetectByExtension(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.pdf")
	os.WriteFile(p, []byte("%PDF-1.4"), 0o644)
	f, _ := os.Open(p)
	defer f.Close()
	if got := Detect(f, "f.pdf"); got != "application/pdf" {
		t.Fatalf("Detect = %q, want application/pdf", got)
	}
}

func TestDetectSniffsExtensionless(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "notes")
	os.WriteFile(txt, []byte("plain old text\n"), 0o644)
	f, _ := os.Open(txt)
	defer f.Close()
	if got := Detect(f, "notes"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Detect(text) = %q", got)
	}
	// Read position must be restored for the caller (serving reuses the handle).
	buf := make([]byte, 5)
	n, _ := f.Read(buf)
	if string(buf[:n]) != "plain" {
		t.Fatalf("file position not rewound: read %q", buf[:n])
	}

	bin := filepath.Join(dir, "blob")
	os.WriteFile(bin, []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, 0o644)
	fb, _ := os.Open(bin)
	defer fb.Close()
	if got := Detect(fb, "blob"); !strings.HasPrefix(got, "application/octet-stream") {
		t.Fatalf("Detect(binary) = %q", got)
	}
}

func TestCompressible(t *testing.T) {
	cases := []struct {
		mime string
		want bool
	}{
		{"text/plain; charset=utf-8", true},
		{"text/html; charset=utf-8", true},
		{"text/csv", true},
		{"text/markdown", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/javascript", true},
		{"image/svg+xml", true},        // the one image type that is really text
		{"application/geo+json", true}, // +json suffix
		{"application/rss+xml", true},  // +xml suffix
		{"application/x-ndjson", true},
		// Already-compressed or opaque payloads: spending CPU on these buys
		// nothing and costs the exact Content-Length.
		{"image/png", false},
		{"image/jpeg", false},
		{"video/mp4", false},
		{"audio/mpeg", false},
		{"application/pdf", false}, // viewable, but internally deflated already
		{"application/zip", false},
		{"application/octet-stream", false},
		{"", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		if got := Compressible(tc.mime); got != tc.want {
			t.Errorf("Compressible(%q) = %v, want %v", tc.mime, got, tc.want)
		}
	}
}

// GalleryPlayable is the gate on turning an existing share into a gallery,
// and it exists because neither of the two rules that already classify a file
// can answer the question.
//
// Viewable passes any image/*, so it calls a HEIC viewable when no browser
// shows one; mediaKind buckets a HEIC as a photo on purpose, so a phone's
// camera roll lays out correctly. Tiling a file is not the same claim as
// being able to play it, and this is the one that has to be strict: being
// wrong the permissive way publishes a gallery of broken tiles.
func TestGalleryPlayableIsStricterThanViewable(t *testing.T) {
	for _, tc := range []struct {
		mime string
		want bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"image/gif", true},
		{"image/webp", true},
		{"image/avif", true},
		{"video/mp4", true},
		{"video/webm", true},
		{"audio/mpeg", true},
		{"audio/mp4", true},
		{"audio/wav", true},
		{"image/jpeg; charset=binary", true},
		// Aliases for containers browsers do play, which a sniffer or a
		// distribution's mime table answers instead of the canonical name.
		{"video/x-m4v", true},
		{"audio/wave", true},
		{"audio/x-m4a", true},
		{"audio/x-flac", true},
		{"IMAGE/JPEG", true},
		// The traps. Every one of these is Viewable.
		{"image/heic", false},
		{"image/heif", false},
		{"image/tiff", false},
		{"image/x-canon-cr2", false},
		{"video/quicktime", false},
		{"video/x-matroska", false},
		{"image/svg+xml", false},
		{"text/plain", false},
		{"application/pdf", false},
		// Nothing sniffed yet: a pending entry refuses rather than guesses.
		{"", false},
		{"nonsense", false},
	} {
		if got := GalleryPlayable(tc.mime); got != tc.want {
			t.Errorf("GalleryPlayable(%q) = %v, want %v", tc.mime, got, tc.want)
		}
	}
}

// The traps are worth stating as a relationship, not just as rows: if these
// two ever agree, the strict list has been widened into the loose one.
func TestGalleryPlayableRefusesTypesViewableAccepts(t *testing.T) {
	for _, mt := range []string{"image/heic", "video/quicktime", "application/pdf"} {
		if !Viewable(mt) {
			t.Fatalf("premise broken: Viewable(%q) is false, so this proves nothing", mt)
		}
		if GalleryPlayable(mt) {
			t.Errorf("GalleryPlayable(%q) must refuse what only Viewable accepts", mt)
		}
	}
}

// detectBytes is Detect over content written to a file named name.
func detectBytes(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := Detect(f, name)
	if pos, _ := f.Seek(0, 1); pos != 0 {
		t.Fatalf("%s: position %d after Detect, want 0", name, pos)
	}
	return got
}

// An extension mapped to an XML or JSON type is believed only for content
// that is text: Debian's mime table maps .pkg, a macOS installer, to an
// +xml type, and that installer must not get a View link. Text in those
// types, and every other type, keeps what its extension says.
func TestAStructuredTextTypeNeedsTextContent(t *testing.T) {
	if err := mime.AddExtensionType(".pkg", "application/vnd.apple.installer+xml"); err != nil {
		t.Fatal(err)
	}
	installer := append([]byte("xar!\x00\x1c\x00\x01"), bytes.Repeat([]byte{0x78, 0xda, 0x00, 0x9c}, 200)...)
	if got := detectBytes(t, "Setup.pkg", installer); got != "application/octet-stream" || Viewable(got) {
		t.Errorf("binary .pkg = %q (viewable %v), want application/octet-stream, not viewable", got, Viewable(got))
	}
	xmlPkg := []byte(`<?xml version="1.0"?><installer-gui-script/>`)
	if got := detectBytes(t, "dist.pkg", xmlPkg); got != "application/vnd.apple.installer+xml" {
		t.Errorf("XML .pkg = %q, want its mapped type", got)
	}
	if got := detectBytes(t, "data.json", []byte{0x7b, 0x00, 0x01, 0x7d}); got != "application/octet-stream" {
		t.Errorf("binary .json = %q, want application/octet-stream", got)
	}
	// A multi-byte character cut by the 512-byte window is still text.
	cut := append(bytes.Repeat([]byte("a"), 511), []byte("é")...)
	if got := detectBytes(t, "big.json", cut); !strings.HasPrefix(got, "application/json") {
		t.Errorf("UTF-8 .json cut mid-character = %q, want application/json", got)
	}
	utf16 := []byte{0xFF, 0xFE, '<', 0, 'a', 0, '/', 0, '>', 0}
	if got := detectBytes(t, "doc.xml", utf16); !strings.Contains(got, "xml") {
		t.Errorf("UTF-16 .xml = %q, want an XML type", got)
	}
	if got := detectBytes(t, "empty.xml", nil); !strings.Contains(got, "xml") {
		t.Errorf("empty .xml = %q, want an XML type", got)
	}
	// Every other type is decided by its extension, whatever the bytes.
	if got := detectBytes(t, "f.pdf", []byte{0, 1, 2, 3}); got != "application/pdf" {
		t.Errorf("binary .pdf = %q, want application/pdf", got)
	}
	if got := detectBytes(t, "f.png", []byte{0, 1, 2, 3}); got != "image/png" {
		t.Errorf("binary .png = %q, want image/png", got)
	}
}
