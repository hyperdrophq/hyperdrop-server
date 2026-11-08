// Package domainconn is a server's side of a free name, derived from the
// facts the server holds, and the rule for when that deserves a notice. It
// is pure (no I/O, no clock) so the server can import it: the server
// announces a domain problem by push with the same states and the same rule
// the clients show.
package domainconn

import (
	"strings"
	"time"
)

// Connection is one state; every client renders it with Label.
type Connection string

const (
	None            Connection = "none"
	PendingApproval Connection = "pending-approval"
	Connected       Connection = "connected"
	// Unauthorized: the registry refuses this server's token. The account
	// still owns the name; this server must be connected again.
	Unauthorized Connection = "unauthorized"
	Silent       Connection = "silent"
	Failing      Connection = "failing"
	// Waiting: approved, but the registry holds the first publication back
	// (a shared limit, or the server not reachable yet). The server retries
	// on its own.
	Waiting Connection = "waiting-to-publish"
)

// CheckInWindow is how long a server may go without a successful heartbeat
// before its connection reads "Not checking in": three of its twelve-hour
// heartbeats, the same window the registry applies from its side.
const CheckInWindow = 36 * time.Hour

var labels = map[Connection]string{
	None: "No domain", PendingApproval: "Waiting for approval", Connected: "Connected",
	Unauthorized: "Not connected", Silent: "Not checking in", Failing: "DNS update failing",
	Waiting: "Waiting to publish",
}

func (c Connection) Label() string { return labels[c] }

// NeedsAttention reports the states a person has to act on: the registry
// refusing this server, a server that stopped checking in, and DNS updates
// failing. Waiting for approval is the person's own doing, waiting to
// publish resolves itself and no domain at all is a choice.
func (c Connection) NeedsAttention() bool {
	switch c {
	case Unauthorized, Silent, Failing:
		return true
	default:
		return false
	}
}

// Facts is what the server knows about its free name.
type Facts struct {
	Configured     bool   // a name is published for this server
	Enrolling      bool   // a claim waits for the account's approval
	LastClaimError string // the registry's answer to the pending claim
	LastError      string // the last heartbeat's failure
	LastUpdate     int64  // unix seconds of the last successful heartbeat
}

// approvalPrompt is how the registry answers a claim nobody has approved
// yet; any other answer to a pending claim comes after the approval.
const approvalPrompt = "Sign in to approve"

// PublicationHeld reports a pending claim past its approval and held back
// by the registry.
func (f Facts) PublicationHeld() bool {
	return f.Enrolling && f.LastClaimError != "" && !strings.HasPrefix(f.LastClaimError, approvalPrompt)
}

// RegistryRefused reports a heartbeat error meaning the registry no longer
// honours this server's token, matched by text, which is all the API carries.
func RegistryRefused(lastError string) bool {
	return strings.Contains(lastError, "does not know this token") || strings.Contains(lastError, "has been released")
}

// Derive answers the state at now. A pending enrollment wins over
// everything: the server is between names until it is approved or
// cancelled, and once approved it waits for the registry to publish.
func Derive(f Facts, now time.Time) Connection {
	switch {
	case f.PublicationHeld():
		return Waiting
	case f.Enrolling:
		return PendingApproval
	case !f.Configured:
		return None
	case RegistryRefused(f.LastError):
		return Unauthorized
	case f.LastError != "":
		return Failing
	case f.LastUpdate == 0 || now.Unix()-f.LastUpdate > int64(CheckInWindow.Seconds()):
		return Silent
	default:
		return Connected
	}
}

// Memory is what an announcer remembers between readings: the last state,
// and whether that state was one that needed attention.
type Memory struct {
	State     Connection `json:"state"`
	Attention bool       `json:"attention"`
}

// Notice is what a reading deserves.
type Notice int

const (
	NoNotice  Notice = iota
	Problem          // the state changed into one that needs attention
	Recovered        // connected again after an announced problem
)

// Next folds one reading into the memory. A state met for the first time
// (known false) is remembered without a notice, so a server starting up, or
// an announcer meeting a domain for the first time, does not re-announce
// what was already true.
func Next(prev Memory, known bool, cur Connection) (Memory, Notice) {
	next := Memory{State: cur, Attention: cur.NeedsAttention()}
	switch {
	case !known || cur == prev.State:
		return next, NoNotice
	case cur.NeedsAttention():
		return next, Problem
	case cur == Connected && prev.Attention:
		return next, Recovered
	default:
		return next, NoNotice
	}
}
