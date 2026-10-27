// Package signinannounce decides which computers signed in by a phone a
// client tells its user about, and in what words. It is pure: no I/O, no
// clock, no platform. The server's deviceSignedIn push and every client's
// banner word one sign-in from this package, so a phone and a computer of
// the account say the same thing about it.
package signinannounce

import (
	"sort"
	"strings"
	"time"
)

// Window bounds how far back a device announces: a sign-in older than this
// is never announced, so a device set up later does not replay old ones.
const Window = 7 * 24 * time.Hour

// Title and Action are the notification's title and its one action, which
// signs the computer out.
const (
	Title  = "A computer signed in"
	Action = "Sign Out"
)

// SignIn is one computer a phone signed in. TokenID is the computer's token,
// which Sign Out revokes; Label is the name the computer gave itself (the
// sanitised label, without the server's "Phone sign-in: " prefix);
// Platform is its client platform (macos, windows, linux); ApprovedBy is
// the approving device's label; Username is the account.
type SignIn struct {
	TokenID    string    `json:"tokenId"`
	Label      string    `json:"label"`
	Platform   string    `json:"platform"`
	ApprovedBy string    `json:"approvedBy"`
	Username   string    `json:"username"`
	At         time.Time `json:"at"`
}

// LabelPrefix is what the server writes before a computer's own label on the
// token a phone signed in.
const LabelPrefix = "Phone sign-in: "

// LabelOf is the label a computer gave itself, from the label the server
// stored on its token: LabelPrefix removed once, a label without it as is.
func LabelOf(stored string) string { return strings.TrimPrefix(stored, LabelPrefix) }

// systems are the words for the client platforms a sign-in names.
var systems = map[string]string{"macos": "macOS", "windows": "Windows", "linux": "Linux", "ios": "iOS", "android": "Android"}

// PlatformName is the word for a client platform as every sentence about a
// computer's sign-in shows it: the notification here and the approving
// phone's question in core/judge. A platform with no word is shown as sent,
// trimmed; a blank one is "".
func PlatformName(platform string) string {
	p := strings.TrimSpace(platform)
	if w, ok := systems[p]; ok {
		return w
	}
	return p
}

// quoteMarks turns every double quotation mark into an apostrophe.
var quoteMarks = strings.NewReplacer(`"`, "'", "“", "'", "”", "'", "„", "'", "‟", "'", "＂", "'")

// SafeLabel is label with every double quotation mark (straight,
// typographic or fullwidth) turned into an apostrophe, so a label shown
// between double quotes cannot close them and continue in the
// notification's own voice.
func SafeLabel(label string) string { return quoteMarks.Replace(label) }

// Words is the notification for s. It states what happened and who
// approved it, and never reassures: nothing in it reads as a sign that the
// sign-in is safe. The label is quoted through SafeLabel.
func Words(s SignIn) (title, body string) {
	who := `"` + SafeLabel(s.Label) + `"`
	if p := PlatformName(s.Platform); p != "" {
		who += " (" + p + ")"
	}
	approver := strings.TrimSpace(s.ApprovedBy)
	if approver == "" {
		approver = "another device"
	}
	return Title, who + " signed in to " + s.Username + ", approved by " + approver + ". If this wasn't you, sign it out."
}

// Due answers the sign-ins to announce now, oldest first (ties by token
// id): those at most Window old, other than self (the device asking, which
// is never told about its own sign-in), not already in announced, and each
// token once. A sign-in without a token id names nothing to sign out and is
// never due.
func Due(all []SignIn, self string, announced []string, now time.Time) []SignIn {
	skip := make(map[string]bool, len(announced)+1)
	for _, id := range announced {
		skip[id] = true
	}
	if self != "" {
		skip[self] = true
	}
	oldest := now.Add(-Window)
	var out []SignIn
	for _, s := range all {
		if s.TokenID == "" || skip[s.TokenID] || s.At.Before(oldest) {
			continue
		}
		skip[s.TokenID] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].TokenID < out[j].TokenID
	})
	return out
}
