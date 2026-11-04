package api

import (
	"errors"
	"slices"

	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/metadb"
)

// revokedLoss is one source one share loses, as the 409 lists it.
type revokedLoss struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Files  *int   `json:"files,omitempty"`
}

// sourceAccessChanges lists the sources of the account's linked shares that
// flip once s is applied: revoked when the resulting allowlist (or role) no
// longer grants them, restored when it grants them again. The verdict reads
// the allowlist alone (linked.Granted), never the server roots, so a volume
// that is unmounted this minute revokes nothing. losses names every revoke
// among the flips, with the share and its owner's view of how many entries
// the source lists right now; it is what a refused edit reports and what
// confirming it accepts.
//
// Only an edit that sets the allowlist or the role flips anything. An edit
// of anything else (a suspension, a password reset, a quota) leaves every
// source as it stands, even one the current list does not cover, so an
// account holding such a share can still be suspended.
func (h *handler) sourceAccessChanges(u metadb.User, s metadb.Settings) ([]metadb.SourceAccess, []revokedLoss, error) {
	if s.SourceRoots == nil && s.Role == nil {
		return nil, nil, nil
	}
	isAdmin := u.IsAdmin()
	if s.Role != nil {
		isAdmin = *s.Role == metadb.RoleAdmin
	}
	allow := u.SourceRoots
	if s.SourceRoots != nil {
		allow = *s.SourceRoots
	}
	shares, err := h.db.LinkedSharesOf(u.Username)
	if err != nil {
		return nil, nil, err
	}
	var flips []metadb.SourceAccess
	var losses []revokedLoss
	for _, d := range shares {
		for _, src := range d.Sources {
			granted := linked.Granted(isAdmin, allow, src.Path)
			switch {
			case granted && src.Revoked():
				flips = append(flips, metadb.SourceAccess{ShareID: d.ID, Source: src.Path})
			case !granted && !src.Revoked():
				files := h.listedCount(d, src.Path)
				flips = append(flips, metadb.SourceAccess{ShareID: d.ID, Source: src.Path, Revoke: true, Files: files})
				losses = append(losses, revokedLoss{ID: d.ID, Name: d.Name, Source: src.Path, Files: files})
			}
		}
	}
	return flips, losses, nil
}

// listedCount is how many entries one source of d lists right now, filter
// applied; nil when the server has no roots or the folder does not read.
func (h *handler) listedCount(d metadb.Share, source string) *int {
	specs, err := h.dbSpecs(d)
	if err != nil {
		return nil
	}
	for _, spec := range specs {
		if spec.Path != source {
			continue
		}
		spec.Revoked = false
		l, readable := linked.Compose(h.roots, []linked.SourceSpec{spec}, linked.MaxWalk)
		if !readable {
			return nil
		}
		n := len(l.Entries)
		return &n
	}
	return nil
}

// ungranted answers which of sources the owner's allowlist, read again
// now, does not grant. A write that adds sources was admitted against the
// allowlist its request authenticated with, and an admin's narrowing can
// commit in between: that edit's flips are computed from the shares as they
// stood, so a source added under the old list would otherwise serve,
// unrevoked, a folder the account no longer reaches. Asked after the write
// commits, either order of the two commits is covered: a narrowing that
// committed first is what this read sees, and one that commits after finds
// the new source in its own second pass (revokeLateSources).
func (h *handler) ungranted(owner string, sources []string) ([]string, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	u, err := h.db.User(owner)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range sources {
		if !linked.Granted(u.IsAdmin(), u.SourceRoots, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// revokeUngranted revokes the sources a sources PATCH just gave a share
// that ungranted finds the owner may no longer share from.
func (h *handler) revokeUngranted(shareID, owner string, added []string) error {
	lost, err := h.ungranted(owner, added)
	if err != nil || len(lost) == 0 {
		return err
	}
	d, err := h.db.ShareCapped(shareID, 1)
	if err != nil {
		return err
	}
	var flips []metadb.SourceAccess
	for _, src := range d.Sources {
		if slices.Contains(lost, src.Path) && !src.Revoked() {
			flips = append(flips, metadb.SourceAccess{ShareID: d.ID, Source: src.Path, Revoke: true,
				Files: h.listedCount(d, src.Path)})
		}
	}
	if len(flips) == 0 {
		return nil
	}
	_, err = h.db.UpdateUserAccess(owner, metadb.Settings{}, flips, false)
	return err
}

// revokeLateSources is an allowlist edit's second pass: once the edit has
// committed, the account and its shares are read again and any source the
// STORED allowlist and role do not grant is revoked too. A source a create
// or a sources PATCH added after the first pass read the shares, and
// committed before this edit did, is invisible to that first pass;
// ungranted covers the other order. The stored list, not the request's, is
// the verdict, because a later edit may have committed since: its own pass
// judged against its list, and this one must not revoke what that list
// grants. Each flip is its own write, and one whose share or source has
// gone meanwhile (the racing create refused itself) is skipped. An edit of
// neither the allowlist nor the role has no second pass.
func (h *handler) revokeLateSources(username string, s metadb.Settings) error {
	if s.SourceRoots == nil && s.Role == nil {
		return nil
	}
	u, err := h.db.User(username)
	if err != nil {
		return err
	}
	stored := u.SourceRoots
	flips, _, err := h.sourceAccessChanges(u, metadb.Settings{SourceRoots: &stored})
	if err != nil {
		return err
	}
	for _, f := range flips {
		if !f.Revoke {
			continue
		}
		_, err := h.db.UpdateUserAccess(u.Username, metadb.Settings{}, []metadb.SourceAccess{f}, false)
		if err != nil && !errors.Is(err, metadb.ErrNotFound) && !errors.Is(err, metadb.ErrNotASource) {
			return err
		}
	}
	return nil
}
