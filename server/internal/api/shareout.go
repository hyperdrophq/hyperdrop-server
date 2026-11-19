package api

import (
	"hyperdrop/server/internal/linked"
	"hyperdrop/server/internal/mimetype"
	"time"
)

// shareOut is the sanitized share view for API responses: passwordHash
// never appears here. hasPassword is the signal every response carries;
// password itself is set by getShare alone, for the share's owner.
type shareOut struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Folder      bool       `json:"folder,omitempty"`
	Entry       string     `json:"entry,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	ModifiedAt  *time.Time `json:"modifiedAt,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	HasPassword bool       `json:"hasPassword,omitempty"`
	// Password is the share's password, set by getShare alone for the
	// owner's bearer: never in a listing, the change feed, the watch, a
	// bulk edit or a public route.
	Password string `json:"password,omitempty"`
	// HasPoster reports a stored preview sidecar, so a client can fetch the
	// thumbnail without probing and 404ing per share.
	HasPoster bool `json:"hasPoster,omitempty"`
	// Media marks a GALLERY: its public link opens the pictures instead of
	// the file listing. Unlike an inbox it is NOT excluded from the
	// default listing, being an ordinary share you hand out.
	Media bool `json:"media,omitempty"`
	// Listing forces the file listing on a share of ONE file, which
	// /share/{id} otherwise redirects straight to.
	Listing bool `json:"listing,omitempty"`
	// LinksOff says the owner turned the share's public links off: every
	// public route answers the links-off page instead of the share. Absent
	// when the links are on, which is what an older server's share reads as.
	LinksOff bool `json:"linksOff,omitempty"`
	// Copying says the share is a duplicate still being filled: its files,
	// tiles and poster are not all in yet. Absent once the copy is complete,
	// which is what a client waiting on the copy reads.
	Copying bool `json:"copying,omitempty"`
	// Inbox marks an INBOX (a container strangers fill through the public
	// /receive/{id} page); Note, Closed and the caps travel with it. The default
	// listing excludes inboxes: clients ask for them with ?kind=receive.
	Inbox bool `json:"receive,omitempty"`
	// Text marks a TEXT share: one text file the link opens as that file. It
	// takes no other View answer, no second file and no delete (409 text-share).
	Text     bool   `json:"text,omitempty"`
	Note     string `json:"note,omitempty"`
	Closed   bool   `json:"closed,omitempty"`
	MaxBytes int64  `json:"maxBytes,omitempty"`
	MaxFiles int    `json:"maxFiles,omitempty"`
	// Source names the server folder a LINKED share serves live; SourceMissing
	// says that folder cannot be read right now.
	Source        string `json:"source,omitempty"`
	SourceMissing bool   `json:"sourceMissing,omitempty"`
	// Sources is every source of a linked share (one entry for a
	// one-source share); with several, each file lists under its
	// source's base name.
	Sources []string `json:"sources,omitempty"`
	// Linked is what each source's filter does, keyed by source: whether
	// it is fixed to what it held when it was picked, and how many paths
	// it hides. Present only for sources that have a filter; the lists
	// themselves never travel.
	Linked map[string]linked.SourceState `json:"linked,omitempty"`
	// Notify says whether arrivals announce themselves on the owner's
	// clients. A POINTER because it is present on inboxes only and
	// ALWAYS present there: a client must read a definite value rather than
	// infer one from an absent omitempty field.
	Notify *bool `json:"notify,omitempty"`
	// SeenAt is the owner's read watermark; absent until first set.
	SeenAt *time.Time `json:"seenAt,omitempty"`
	// PinnedAt is when the owner pinned the share to the top of their list;
	// absent when it is not pinned. Clients order pinned shares first, the
	// most recent pin on top.
	PinnedAt *time.Time `json:"pinnedAt,omitempty"`
	// Incoming lists a request's uploads IN FLIGHT (claimed name, bytes
	// received, sender's declared total), so the owner watches an upload
	// happen rather than only its result. Authed reads fill it (getShare,
	// the inbox listing, the change feed), and the owner's watch answers it
	// as it moves (inboxprogress.go); it is never on any public surface.
	Incoming []incomingOut `json:"incoming,omitempty"`
	// Pending mirrors scheduled password/expiry changes: hashes stay
	// server-only, clients see only kind/when/set-vs-clear.
	Pending []pendingOut `json:"pending,omitempty"`
	Files   []fileOut    `json:"files"`
	// Folders are the share's EXPLICIT folder records (an empty folder is
	// one); folders a file path implies are read off Files. Never
	// windowed: the database caps the list.
	Folders []string `json:"folders,omitempty"`
	// FileCount and TotalSize describe the WHOLE share, always. Files may be
	// a window onto it in a listing, and then FilesTruncated says so: a
	// client showing "20,000 files" reads it from here, and one that needs
	// the paths fetches GET /api/shares/{id}, which is never capped.
	FileCount      int   `json:"fileCount"`
	FilesTruncated bool  `json:"filesTruncated,omitempty"`
	TotalSize      int64 `json:"totalSize"`
	// Visitors is how many distinct visitors have read the share: one per
	// hd_visitor cookie, or per address and User-Agent for a request without
	// one. Never windowed and never the owner's own bearer reads.
	Visitors int `json:"visitors"`
}

type pendingOut struct {
	Kind    string    `json:"kind"`
	ApplyAt time.Time `json:"applyAt"`
	Clear   bool      `json:"clear,omitempty"`
}

type incomingOut struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Total int64  `json:"total"`
	// By groups this upload with the rest of one sender's share, so a client
	// can say "2 senders" and announce each one's share once. Empty for a
	// sender that carried no visitor cookie.
	By string `json:"by,omitempty"`
}

// incomingFor maps an inbox's in-flight uploads for the authed DTOs: the
// claimed names with the bytes each has received; nil for an ordinary
// share, and for an inbox nobody is uploading into, so the field stays
// absent.
func (h *handler) incomingFor(v shareView) []incomingOut {
	if !v.Inbox {
		return nil
	}
	out := h.claims.incoming(v.ID)
	if len(out) == 0 {
		return nil
	}
	return out
}

// fileOut is a file row as API responses show it: the stored mime stays
// internal; clients get the derived viewable verdict instead.
type fileOut struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Slug     string `json:"slug"`
	SHA256   string `json:"sha256,omitempty"`
	Viewable bool   `json:"viewable"`
	// Pending: declared in the creation manifest, bytes not yet uploaded.
	// (Distinct from the share-level pending scheduled-actions array.)
	Pending bool `json:"pending,omitempty"`
	// Linked: comes from the live walk of one of the share's sources; no
	// upload, no quota, no delete.
	Linked bool `json:"linked,omitempty"`
	// CommittedAt is when the bytes landed, which clients show as the file's
	// date modified. Absent on a pending entry and on a row that has no
	// commit time.
	CommittedAt *time.Time `json:"committedAt,omitempty"`
	AddedAt     *time.Time `json:"addedAt,omitempty"`
	// UploadedBy groups a received file with the rest of one sender's upload.
	// Filled on INBOXES only, by toShareOut: an owner's own upload
	// session is theirs and has no business on the wire.
	UploadedBy string `json:"uploadedBy,omitempty"`
	// HasThumb says a gallery tile (thumbs/<slug>.jpg) stands for this file
	// and is at least as new as the file: the client derives tiles and
	// needs to know which files still want one, without reading the share
	// back. Filled by resolvedRow on a MEDIA share's owner view only; public
	// pages read the tiles themselves.
	HasThumb bool `json:"hasThumb,omitempty"`
	// FileKey is the file's direct-link key. Only the owner's answers carry
	// it (a live share's create, add-files and resume answers fill it from
	// the registry record); toFileOut never sets it and public pages never
	// read it.
	FileKey string `json:"fileKey,omitempty"`
}

func toFileOut(f fileView) fileOut {
	// A file gets its type when its bytes land, so an entry still waiting
	// for them is judged by its name: a client laying out a share mid-upload
	// needs to know which entries it will be able to open.
	return fileOut{Path: f.Path, Size: f.Size, Slug: f.Slug, SHA256: f.SHA256,
		Viewable: mimetype.Viewable(f.MimeOrGuess()), Pending: f.Pending, Linked: f.Linked,
		CommittedAt: f.CommittedAt, AddedAt: f.AddedAt}
}

// resolvedRow is a share as the authed read routes answer it: the sanitized
// DTO plus the two per-row file-layer lookups toShareOut deliberately leaves
// out so it stays a pure mapper. HasPoster costs one os.Stat per row,
// bounded by the caller's page limit.
func (h *handler) resolvedRow(v shareView) shareOut {
	so := toShareOut(v)
	so.HasPoster = h.fs.HasPoster(v.ID)
	so.Incoming = h.incomingFor(v)
	h.fillFileKeys(&so)
	if v.Media {
		// One directory read per share view, never per file, the way the
		// gallery page reads its tiles.
		if tiles, err := h.fs.ThumbTimes(v.ID); err == nil {
			for i := range so.Files {
				so.Files[i].HasThumb = thumbCurrent(v.Files[i], tiles)
			}
		}
	}
	return so
}

// thumbCurrent answers whether the tile written for f still stands for it.
// A stored file's bytes never change under its slug (a replace prunes the
// tile with the row it hands on), so any tile is current; a linked file is
// the NAS's own file and can be overwritten in place, so its tile counts
// only while it is no older than the file's modification time, which the
// walk reports as CommittedAt.
func thumbCurrent(f fileView, tiles map[string]time.Time) bool {
	at, ok := tiles[f.Slug]
	if !ok {
		return false
	}
	if f.Linked && f.CommittedAt != nil && at.Before(*f.CommittedAt) {
		return false
	}
	return true
}

func toShareOut(v shareView) shareOut {
	files := make([]fileOut, 0, len(v.Files))
	for _, f := range v.Files {
		out := toFileOut(f)
		if v.Inbox {
			out.UploadedBy = f.UploadSession
		}
		files = append(files, out)
	}
	var pending []pendingOut
	for _, p := range v.Scheduled {
		pending = append(pending, pendingOut{Kind: p.Kind, ApplyAt: p.ApplyAt, Clear: p.Clear})
	}
	// Totals describes the whole share whether or not Files is a window, so
	// a truncated listing row still reports real figures.
	count, total := v.Totals()
	out := shareOut{
		ID: v.ID, Name: v.Name, Folder: v.Folder, Entry: v.Entry,
		CreatedAt: v.CreatedAt, ModifiedAt: v.ModifiedAt,
		ExpiresAt: v.ExpiresAt, HasPassword: v.PasswordHash != "",
		Media:    v.Media,
		Listing:  v.Listing,
		LinksOff: v.LinksOff(),
		Copying:  v.CopyingFrom != "",
		Inbox:    v.Inbox, Text: v.Text, Note: v.Note, Closed: v.Closed,
		MaxBytes: v.MaxBytes, MaxFiles: v.MaxFiles,
		Source: v.Source(), SourceMissing: v.SourceMissing, Sources: v.SourceList(),
		Linked:  v.LinkedState,
		Pending: pending, Files: files, Folders: v.Folders,
		FileCount: count, FilesTruncated: v.Truncated, TotalSize: total,
		Visitors: v.Visitors, PinnedAt: v.PinnedAt,
	}
	if v.Inbox {
		notify := !v.NotifyOff
		out.Notify = &notify
		out.SeenAt = v.SeenAt
		out.MaxFiles = inboxFileLimit(v.MaxFiles, v.Committed)
	}
	return out
}
