// Package updatenotice decides which reminders about a server update are
// due now, and words them for any device. The server's pusher sends each
// one to admins' iPhones once and the Mac posts each one once when it
// refreshes status; both read the same list from GET /api/server/settings,
// keyed so a reminder is never repeated. Pure: no I/O and no clock of its
// own (server/pureimports_test.go lists it).
package updatenotice

import (
	"strings"
	"unicode/utf8"

	"hyperdrop/core/releasemanifest"
)

// The self-update states a server reports (GET /api/server/settings
// selfUpdate).
const (
	On     = "on"     // installs each newer release itself
	Off    = "off"    // an admin turned automatic updates off
	NAS    = "nas"    // Package Center owns the binary
	Failed = "failed" // the newest release did not install itself
	Manual = "manual" // this box cannot install on its own
)

// Facts is what the server knows about its update.
type Facts struct {
	Running, Latest string
	SelfUpdate      string
	FailedVersion   string
	FailedReason    string
}

// Notice is one reminder. Key is stable for as long as the reminder means
// the same thing, so a sender that remembers keys sends each one once.
type Notice struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

const maxReason = 160

// Due answers the reminders due now, the most pressing first. Nothing is due
// while the server is current or updates itself. A failed attempt is due once
// per version, and stands in for the newest release's own notice when that
// release is the one that failed; a newer release is due once. A failure is
// due even before the manifest is read (a box that rolled a failed update
// back restarts without it): the failed version then stands as the newest
// release. No reminder carries a date: whether an app still works with the
// server is the version window's question (core/api.Window), not a deadline.
func Due(f Facts) []Notice {
	if f.Latest == "" && f.SelfUpdate == Failed {
		f.Latest = f.FailedVersion
	}
	if f.Latest == "" || !releasemanifest.Less(f.Running, f.Latest) || f.SelfUpdate == On {
		return nil
	}
	var out []Notice
	failed := f.SelfUpdate == Failed && f.FailedVersion != ""
	if failed {
		out = append(out, Notice{Key: "failed:" + f.FailedVersion,
			Title: "The server could not update itself",
			Body:  "HyperDrop Server " + f.FailedVersion + " did not install: " + reason(f.FailedReason) + " " + action(f.SelfUpdate)})
		if f.FailedVersion == f.Latest {
			return out
		}
	}
	return append(out, Notice{Key: "release:" + f.Latest, Title: "Server update available",
		Body: "HyperDrop Server " + f.Latest + " is out. " + action(f.SelfUpdate)})
}

func action(state string) string {
	switch state {
	case NAS:
		return "Update HyperDrop in Package Center on the NAS."
	case Off:
		return "Automatic updates are off: update it with Update Server in HyperDrop, or turn them back on."
	case Manual:
		return "This server cannot install updates on its own: update it with Update Server in HyperDrop."
	default:
		return "Update it with Update Server in HyperDrop."
	}
}

func reason(r string) string {
	r = strings.TrimSuffix(strings.TrimSpace(r), ".")
	if r == "" {
		return "the update failed."
	}
	if utf8.RuneCountInString(r) > maxReason {
		r = string([]rune(r)[:maxReason]) + "…"
	}
	return r + "."
}
