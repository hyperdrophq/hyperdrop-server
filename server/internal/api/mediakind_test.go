package api

import "testing"

func TestMediaKind(t *testing.T) {
	for _, tc := range []struct{ mime, name, want string }{
		// The MIME the server sniffed at commit answers first.
		{"image/jpeg", "a.jpg", kindPhoto},
		{"image/png", "a.png", kindPhoto},
		{"image/gif", "a.gif", kindPhoto},
		{"image/webp", "a.webp", kindPhoto},
		{"video/mp4", "a.mp4", kindVideo},
		{"video/quicktime", "a.mov", kindVideo},
		{"audio/mpeg", "a.mp3", kindAudio},
		{"audio/mp4", "a.m4a", kindAudio},
		{"application/pdf", "a.pdf", kindFile},
		{"text/plain; charset=utf-8", "a.txt", kindFile},
		// Parameters and case never change the verdict.
		{"IMAGE/JPEG; charset=binary", "a.jpg", kindPhoto},
		// An SVG is a document that happens to carry an image type. It is
		// sandboxed for the same reason an uploaded page is, and a tile in a
		// photo grid is not where arbitrary vector content belongs.
		{"image/svg+xml", "a.svg", kindFile},
		// A pending manifest entry has no sniffed type yet, and a bare Linux
		// box's mime table knows none of these extensions.
		{"", "a.heic", kindPhoto},
		{"", "a.HEIF", kindPhoto},
		{"", "a.avif", kindPhoto},
		{"", "a.dng", kindPhoto},
		{"", "a.cr2", kindPhoto},
		{"", "a.mov", kindVideo},
		{"", "a.mkv", kindVideo},
		{"", "a.webm", kindVideo},
		{"", "a.m4v", kindVideo},
		{"", "a.flac", kindAudio},
		{"", "a.opus", kindAudio},
		{"", "a.m4a", kindAudio},
		{"", "a.aiff", kindAudio},
		// Nothing to go on either way.
		{"", "a.bin", kindFile},
		{"", "noextension", kindFile},
		{"", "", kindFile},
		// A path, not just a basename: the classifier is handed relpaths.
		{"", "trip/day one/IMG_0001.HEIC", kindPhoto},
	} {
		if got := mediaKind(tc.mime, tc.name); got != tc.want {
			t.Errorf("mediaKind(%q, %q) = %q, want %q", tc.mime, tc.name, got, tc.want)
		}
	}
}

func TestMediaKindPrefersTheSniffedTypeOverTheExtension(t *testing.T) {
	// A .txt that really holds a JPEG was sniffed as one at commit; the
	// gallery shows what the browser will actually render.
	if got := mediaKind("image/jpeg", "notes.txt"); got != kindPhoto {
		t.Errorf("mediaKind = %q, want %q", got, kindPhoto)
	}
}
