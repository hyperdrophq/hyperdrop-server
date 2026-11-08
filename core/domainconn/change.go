package domainconn

import (
	"strconv"
	"time"
)

// Change is one move of a server's address: From is "" when the server had
// no domain.
type Change struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// ChangesKept is how many changes a server remembers.
const ChangesKept = 8

// ChangeShownFor is how long a change stays in the list.
const ChangeShownFor = 7 * 24 * time.Hour

// RecordChange appends c to list, drops entries older than ChangeShownFor
// and keeps the newest ChangesKept, oldest first.
func RecordChange(list []Change, c Change, now time.Time) []Change {
	out := ChangesShown(append(append([]Change{}, list...), c), now)
	if len(out) > ChangesKept {
		out = out[len(out)-ChangesKept:]
	}
	return out
}

// ChangesShown is the entries younger than ChangeShownFor, oldest first.
func ChangesShown(list []Change, now time.Time) []Change {
	out := []Change{}
	for _, c := range list {
		if now.Sub(c.At) < ChangeShownFor {
			out = append(out, c)
		}
	}
	return out
}

// ChangeNotice is the words an administrator is told a change in.
type ChangeNotice struct {
	Key   string    `json:"key"`
	Title string    `json:"title"`
	Body  string    `json:"body"`
	At    time.Time `json:"at"`
}

// NoticeOf words a change. Its Key is stable per change, so a client
// announces each change once.
func NoticeOf(c Change) ChangeNotice {
	body := "This HyperDrop server now uses " + c.To + " as its address, and HyperDrop apps follow it there. If no administrator of this server made this change, change your password now: that signs out every other device."
	if c.From != "" {
		body = "This HyperDrop server moved from " + c.From + " to " + c.To + ", and HyperDrop apps follow it to the new address. If no administrator of this server made this change, change your password now: that signs out every other device."
	}
	return ChangeNotice{
		Key:   "domain:" + strconv.FormatInt(c.At.UnixNano(), 10) + ":" + c.To,
		Title: "Your server's address changed",
		Body:  body,
		At:    c.At,
	}
}
