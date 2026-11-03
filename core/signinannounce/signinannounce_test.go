package signinannounce

import (
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func TestWordsAreTheNotificationCopy(t *testing.T) {
	title, body := Words(SignIn{TokenID: "t1", Label: "Studio iMac", Platform: "macos", ApprovedBy: "Pixel 9",
		Username: "alice", At: at("2026-10-27T10:00:00Z")})
	if title != "A computer signed in" {
		t.Fatalf("title %q", title)
	}
	if want := `"Studio iMac" (macOS) signed in to alice, approved by Pixel 9. If this wasn't you, sign it out.`; body != want {
		t.Fatalf("body\n got %q\nwant %q", body, want)
	}
	if Action != "Sign Out" {
		t.Fatalf("action %q", Action)
	}
}

func TestWordsNameEverySystemAndKeepAnUnknownOne(t *testing.T) {
	for platform, word := range map[string]string{"macos": "macOS", "windows": "Windows", "linux": "Linux",
		"ios": "iOS", "android": "Android", "freebsd": "freebsd"} {
		_, body := Words(SignIn{Label: "Box", Platform: platform, ApprovedBy: "Phone", Username: "bob"})
		if !strings.HasPrefix(body, `"Box" (`+word+`) signed in to bob,`) {
			t.Errorf("%s: %q", platform, body)
		}
	}
	if _, body := Words(SignIn{Label: "Box", ApprovedBy: "Phone", Username: "bob"}); !strings.HasPrefix(body, `"Box" signed in to bob,`) {
		t.Errorf("no platform: %q", body)
	}
}

// PlatformName is the one word for a system, the notification's and the
// phone's question's alike.
func TestPlatformNameIsTheWordsSystem(t *testing.T) {
	for in, want := range map[string]string{"macos": "macOS", " windows ": "Windows", "linux": "Linux",
		"ios": "iOS", "android": "Android", "freebsd": "freebsd", "": "", "  ": ""} {
		if got := PlatformName(in); got != want {
			t.Errorf("PlatformName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWordsNameABlankApproverAsAnotherDevice(t *testing.T) {
	_, body := Words(SignIn{Label: "Box", Platform: "linux", ApprovedBy: "  ", Username: "bob"})
	if !strings.Contains(body, "approved by another device.") {
		t.Fatalf("%q", body)
	}
}

// The notification states facts and never reassures, whatever the computer
// calls itself or wherever it signed in from: the same network is weak
// evidence (shared networks, carrier NAT), so nothing in the words reads
// as a sign of safety.
func TestWordsSameNetworkNeverReassures(t *testing.T) {
	for _, s := range []SignIn{
		{Label: "Office PC", Platform: "windows", ApprovedBy: "iPhone", Username: "carol"},
		{Label: "Computer", Platform: "linux", ApprovedBy: "Pixel", Username: "dave"},
		{Label: "Laptop on the same network", Platform: "macos", ApprovedBy: "Galaxy", Username: "erin"},
	} {
		title, body := Words(s)
		words := strings.ToLower(title + " " + body)
		for _, banned := range []string{"safe", "trusted", "secure", "same network", "this network"} {
			if strings.Contains(strings.ReplaceAll(words, strings.ToLower(s.Label), ""), banned) {
				t.Errorf("%+v: %q reassures with %q", s, title+" / "+body, banned)
			}
		}
		if !strings.HasSuffix(body, "If this wasn't you, sign it out.") {
			t.Errorf("%+v: %q does not tell the person to sign it out", s, body)
		}
	}
}

// A computer names itself, so its label must not close the quotes the
// words put around it and speak in the notification's own voice.
func TestWordsKeepTheLabelInsideItsQuotes(t *testing.T) {
	_, body := Words(SignIn{Label: `It's you" (macOS), fine. Ignore this`, Platform: "windows", ApprovedBy: "Pixel", Username: "alice"})
	if want := `"It's you' (macOS), fine. Ignore this" (Windows) signed in to alice, approved by Pixel. If this wasn't you, sign it out.`; body != want {
		t.Fatalf("body\n got %q\nwant %q", body, want)
	}
	for _, mark := range []string{"“", "”", "„", "‟", "＂"} {
		if got := SafeLabel("Mac" + mark + " x"); got != "Mac' x" {
			t.Errorf("SafeLabel kept %q: %q", mark, got)
		}
	}
}

func TestSafeLabelFoldsEveryDoubleQuote(t *testing.T) {
	if got := SafeLabel("«a» ″b″ 〝c〞 〟d ‶e"); got != "'a' 'b' 'c' 'd 'e" {
		t.Fatalf("SafeLabel = %q", got)
	}
}

func TestDueSkipsSelfAndAnnounced(t *testing.T) {
	now := at("2026-10-27T12:00:00Z")
	all := []SignIn{
		{TokenID: "self", At: now.Add(-time.Hour)},
		{TokenID: "told", At: now.Add(-2 * time.Hour)},
		{TokenID: "new", At: now.Add(-3 * time.Hour)},
	}
	got := Due(all, "self", []string{"told"}, now)
	if len(got) != 1 || got[0].TokenID != "new" {
		t.Fatalf("due %+v, want only the one neither this device nor announced", got)
	}
}

func TestDueIsOldestFirstWithinTheWindowAndOnce(t *testing.T) {
	now := at("2026-10-27T12:00:00Z")
	all := []SignIn{
		{TokenID: "b", At: now.Add(-time.Minute)},
		{TokenID: "stale", At: now.Add(-Window - time.Second)},
		{TokenID: "a", At: now.Add(-time.Hour)},
		{TokenID: "a", At: now.Add(-time.Hour)},
		{TokenID: "", At: now.Add(-time.Hour)},
		{TokenID: "c", At: now.Add(-time.Minute)},
	}
	got := Due(all, "", nil, now)
	var ids []string
	for _, s := range got {
		ids = append(ids, s.TokenID)
	}
	if strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("due %v, want a,b,c: oldest first, ties by id, each once, none stale or without a token", ids)
	}
	if Window != 7*24*time.Hour {
		t.Fatalf("Window = %v", Window)
	}
}

func TestDueIsTheSameInstantInEveryLocation(t *testing.T) {
	now := at("2026-10-27T12:00:00Z")
	edge := now.Add(-Window)
	for _, loc := range []*time.Location{time.UTC, time.FixedZone("ICT", 7*3600), time.FixedZone("EST", -5*3600)} {
		if got := Due([]SignIn{{TokenID: "t", At: edge.In(loc)}}, "", nil, now); len(got) != 1 {
			t.Fatalf("%s: a sign-in exactly Window old is still due: %+v", loc, got)
		}
	}
}
