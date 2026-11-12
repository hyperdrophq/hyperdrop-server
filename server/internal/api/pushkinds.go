package api

import "hyperdrop/core/inboxannounce"

// The notification kinds the server pushes, named as every client names them
// (NotificationKind on the Mac, the push payload's kind on the phone).
const (
	pushKindInboxReceived = "inboxReceived"
	pushKindAccessRevoked = "accessRevoked"
	pushKindDomain        = "domain"
	pushKindServerUpdate  = "serverUpdate"
	// pushKindDomainChanged is the server's address changing, told to every
	// admin (pushdomainchange.go): never muted and never left to a computer.
	pushKindDomainChanged = "domainChanged"
	// pushKindDeviceSignedIn is a computer a phone signed in
	// (pushsignin.go): sent to every other registered device of the
	// account whatever any computer's activity, and never muted.
	pushKindDeviceSignedIn = "deviceSignedIn"
)

// desktopIdleLimit is how recently a computer of the account must have seen
// its owner for the server to leave the announcing to it.
const desktopIdleLimit = inboxannounce.ActiveIdleLimit
