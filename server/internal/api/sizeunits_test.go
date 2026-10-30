package api

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The waiting page's progress line sits beside the figure the sender's app
// shows while it uploads, which is decimal (macOS's ByteCountFormatter, the
// iPhone and the other apps), so the page counts in powers of 1000 too:
// 338,842,326 bytes reads "338.8 MB" in the app and on the page alike. The
// listing and the gallery keep their binary figures (humanSize).
func TestTheWaitingPageCountsSizesInDecimalUnits(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("pages", "waiting.html"))
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`\b1024\b`).Match(body) {
		t.Error("waiting.html counts sizes in powers of 1024")
	}
	if !regexp.MustCompile(`/= ?1000`).Match(body) {
		t.Error("waiting.html has no decimal size formatter")
	}
}
