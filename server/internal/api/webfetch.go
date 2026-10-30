package api

import (
	"log"

	"hyperdrop/core/webbundle"
	"hyperdrop/server/internal/selfupdate"
	"hyperdrop/server/internal/webapp"
)

// webFetchedForKey is the settings row holding the server version the web
// fetch last succeeded for.
const webFetchedForKey = "webapp.fetchedFor"

// webFetchPolicy is the web fetcher's policy: with automatic updates on, the
// fetcher runs on its schedule. With them off it runs when an administrator
// asks, and while a fetch is owed.
type webFetchPolicy struct{ h *handler }

// Allow reports whether a run for t goes ahead.
func (p webFetchPolicy) Allow(t webapp.Trigger) bool {
	if t == webapp.TriggerAsked {
		return true
	}
	if auto, err := selfupdate.AutoIn(p.h.db); err == nil && auto {
		return true
	}
	return p.h.webFetchOwed()
}

// Fetched records that the fetch succeeded for the running version.
func (p webFetchPolicy) Fetched() {
	if err := p.h.db.SetSetting(webFetchedForKey, p.h.version); err != nil {
		log.Printf("web client: recording the fetched version: %v", err)
	}
}

// webFetchOwed reports whether the web client still has to be fetched for
// the running version: no bundle is installed, the installed bundle's
// contract is one this server does not serve, or the last successful fetch
// was for another server version.
func (h *handler) webFetchOwed() bool {
	inst, ok := h.dep.Web.Current()
	if !ok || !webbundle.Serves(inst.Contract, h.version) {
		return true
	}
	v, found, err := h.db.Setting(webFetchedForKey)
	return err != nil || !found || v != h.version
}

// nudgeWebFetch asks the web fetcher for a run now, when there is one.
func (h *handler) nudgeWebFetch() {
	if h.dep.WebFetcher != nil {
		h.dep.WebFetcher.Nudge()
	}
}
