// Package systemfiles carries the provisioner, core/provision/provision.sh,
// byte for byte (TestTheEmbeddedProvisionerIsCoreProvisionSh). The root
// updater runs `hyperdrop-server system-files` with a binary it has just
// verified, and renders the service unit, itself and its two units from the
// provisioner that prints, so a normal update refreshes what an install wrote.
// The server cannot import core/provision, which does I/O, so the script
// lives here as a copy.
package systemfiles

import (
	_ "embed"
	"io"
)

//go:embed provision.sh
var provisioner []byte

// Provisioner answers the embedded provisioner.
func Provisioner() []byte { return append([]byte(nil), provisioner...) }

// Run is the system-files subcommand: it prints the provisioner and exits 0,
// touching nothing else, whatever arguments follow.
func Run(w io.Writer) int {
	if _, err := w.Write(provisioner); err != nil {
		return 1
	}
	return 0
}
