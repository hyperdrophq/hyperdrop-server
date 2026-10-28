package main

import (
	"log"
	"strings"
	"sync"

	"hyperdrop/server/internal/conffile"
	"hyperdrop/server/internal/ddns"
)

// confAddress keeps the address lines of the Synology package's conf
// (HYPERDROP_CONF) naming the server's current address, so the wizard, the
// DSM page and the next start read the truth whichever path changed it: a
// free name is HYPERDROP_DDNS_NAME=<name> with HYPERDROP_DOMAIN empty, an own
// domain the reverse. It edits the conf through conffile, which follows the
// package's conf_set. A zero path (every server but the package) does
// nothing.
type confAddress struct {
	path string
	mu   sync.Mutex
}

// Sync writes d's address lines into the conf when they differ. An empty d
// (no address yet) changes nothing; a failure is logged, never fatal.
func (c *confAddress) Sync(d string) {
	if c == nil || c.path == "" || d == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeConfAddress(c.path, d); err != nil {
		log.Printf("conf: recording the address %s in %s: %v", d, c.path, err)
	}
}

// confAddressValues is what the conf's two address keys hold for d.
func confAddressValues(d string) (domainValue, ddnsName string) {
	if name, ok := strings.CutSuffix(d, "."+ddns.Zone); ok && ddns.ValidName(name) {
		return "", name
	}
	return d, ""
}

// writeConfAddress rewrites the conf at path with d's address lines
// (conffile.Edit: a plain file only, replaced atomically, mode 0600).
func writeConfAddress(path, d string) error {
	domainValue, ddnsName := confAddressValues(d)
	return conffile.Edit(path, func(text string) string {
		return conffile.SetText(conffile.SetText(text, "HYPERDROP_DOMAIN", domainValue), "HYPERDROP_DDNS_NAME", ddnsName)
	})
}
