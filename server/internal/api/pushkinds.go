package api

import "hyperdrop/core/inboxannounce"

// The notification kinds the server pushes, named as every client names them
// (NotificationKind on the Mac, the push payload's kind on the phone).
const (
	pushKindInboxReceived = "inboxReceived"
	pushKindAccessRevoked = "accessRevoked"
	pushKindDomain        = "domain"
	pushKindServerUpdate  = "serverUpdate"
)

// desktopIdleLimit is how recently a computer of the account must have seen
// its owner for the server to leave the announcing to it.
const desktopIdleLimit = inboxannounce.ActiveIdleLimit
