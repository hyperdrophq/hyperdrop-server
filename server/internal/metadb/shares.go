package metadb

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	sqlite3 "modernc.org/sqlite/lib"

	"hyperdrop/server/internal/shareid"
)

// File is one manifest entry, committed or still pending an upload.
type File struct {
	Path, Slug           string
	Size                 int64
	SHA256, Mime         string
	Pending              bool
	CommittedAt, AddedAt *time.Time
	UploadSession        string
}

// Scheduled is one scheduled change; Kind is "password" or "expiry".
type Scheduled struct {
	Kind         string
	ApplyAt      time.Time
	Clear        bool
	PasswordHash string
	ExpiresAt    *time.Time
	// PasswordSealed is the readable copy of the scheduled password (sealpw),
	// bound to PasswordHash; nil = none.
	PasswordSealed []byte
}

// Source is a linked share's source and its filter state. RevokedAt is set
// while the owner's allowlist no longer covers the source: the share then
// lists and serves nothing from it, and RevokedFiles is how many entries it
// listed at that moment (nil when the folder could not be read then).
type Source struct {
	Path         string
	Fixed        bool
	Hidden       int
	RevokedAt    *time.Time
	RevokedFiles *int
}

func (s Source) Revoked() bool { return s.RevokedAt != nil }

// Share is one share and everything the metadata store knows about it.
type Share struct {
	ID, Name, Owner       string
	Folder                bool
	Entry                 string
	Media, Listing, Inbox bool
	Text                  bool // one text file, opened as that file; never an inbox, never another View answer
	Note                  string
	Closed                bool
	MaxBytes              int64
	MaxFiles              int
	NotifyOff             bool
	SeenAt                *time.Time
	PinnedAt              *time.Time // nil = not pinned
	PasswordHash          string
	PasswordGen           int
	PasswordSealed        []byte // the owner's readable copy (sealpw), bound to PasswordHash; nil = none
	CreatedAt             time.Time
	ModifiedAt, ExpiresAt *time.Time
	Bytes                 int64
	Committed, FileCount  int // the counters, always filled
	Visitors              int // distinct visitor tokens, kept by the visitors triggers
	Files                 []File
	Truncated             bool // Files may be a window; then Truncated is true
	Folders               []string
	Scheduled             []Scheduled
	Sources               []Source
}

func (d Share) Linked() bool      { return len(d.Sources) > 0 }
func (d Share) HasPassword() bool { return d.PasswordHash != "" }

// PendingFile is one file a caller declares up front, before it uploads.
type PendingFile struct {
	Path string
	Size int64
}

// CreateOptions is what CreateShare needs to create a share.
type CreateOptions struct {
	ID           string // "" mints one
	Name, Owner  string
	Folder       bool
	Entry        string
	PasswordHash string
	// SealPassword answers the readable copy for the share id the create
	// mints (sealpw.Seal, in the API); nil = no password or none kept. It is
	// called only when PasswordHash is set, and its error creates nothing.
	SealPassword          func(id string) ([]byte, error)
	ExpiresAt             *time.Time
	Media, Listing, Inbox bool
	Text                  bool
	Note                  string
	MaxBytes              int64
	MaxFiles              int
	Sources               []string
	Files                 []PendingFile
	CreatedAt             time.Time // zero = now
}

// newSlug mints a UUIDv4, the public token of one file.
func newSlug() string { return shareid.NewSlug() }

const shareCols = `id, owner, name, folder, entry, media, listing, inbox, note, closed, max_bytes, max_files,
	notify_off, seen_at, pinned_at, password_hash, password_gen, created_at, modified_at, expires_at, bytes, committed, files, visitors, text, password_sealed`

// rowScanner is what *sql.Row and *sql.Rows have in common, so one column
// mapping serves a single-row read and a batched one.
type rowScanner interface{ Scan(dest ...any) error }

// scanShareRow maps one shares row selected in shareCols order onto a Share.
// The child rows (files, folders, scheduled, sources) are the caller's.
func scanShareRow(sc rowScanner) (Share, error) {
	var d Share
	var seen, pinned, modified, expires sql.NullInt64
	var pw sql.NullString
	var created int64
	if err := sc.Scan(
		&d.ID, &d.Owner, &d.Name, &d.Folder, &d.Entry, &d.Media, &d.Listing, &d.Inbox, &d.Note, &d.Closed,
		&d.MaxBytes, &d.MaxFiles, &d.NotifyOff, &seen, &pinned, &pw, &d.PasswordGen, &created, &modified, &expires,
		&d.Bytes, &d.Committed, &d.FileCount, &d.Visitors, &d.Text, &d.PasswordSealed); err != nil {
		return Share{}, err
	}
	d.SeenAt, d.PinnedAt = fromNSPtr(seen), fromNSPtr(pinned)
	d.ModifiedAt, d.ExpiresAt = fromNSPtr(modified), fromNSPtr(expires)
	d.PasswordHash = pw.String
	d.CreatedAt = fromNS(created)
	return d, nil
}

// scheduledCols selects one scheduled row; scanScheduledRow maps it.
const scheduledCols = `kind, apply_at, clear, password_hash, expires_at, password_sealed`

func scanScheduledRow(sc rowScanner, extra ...any) (Scheduled, error) {
	var s Scheduled
	var applyAt int64
	var hash sql.NullString
	var exp sql.NullInt64
	dest := append([]any{&s.Kind, &applyAt, &s.Clear, &hash, &exp, &s.PasswordSealed}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return Scheduled{}, err
	}
	s.ApplyAt, s.PasswordHash, s.ExpiresAt = fromNS(applyAt), hash.String, fromNSPtr(exp)
	return s, nil
}

// sourceCols selects one source of the share_sources rows aliased s, with the
// count of paths hidden under it; scanSourceRow maps it.
const sourceCols = `s.source, s.fixed,
	(SELECT count(*) FROM source_paths p WHERE p.share_id = s.share_id AND p.source = s.source AND p.kind = 'hidden'),
	s.revoked_at, s.revoked_files`

func scanSourceRow(sc rowScanner, extra ...any) (Source, error) {
	var src Source
	var revokedAt, revokedFiles sql.NullInt64
	dest := append([]any{&src.Path, &src.Fixed, &src.Hidden, &revokedAt, &revokedFiles}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return Source{}, err
	}
	src.RevokedAt, src.RevokedFiles = fromNSPtr(revokedAt), fromNullInt(revokedFiles)
	return src, nil
}

// scanShare reads one share and its child rows through fetchPage, the read a
// listing page makes. maxFiles <= 0 reads every file.
func scanShare(tx *sql.Tx, id string, maxFiles int) (Share, error) {
	if !shareid.ValidID(id) {
		return Share{}, ErrNotFound
	}
	shares, err := fetchPage(tx, []string{id}, maxFiles, maxFiles)
	if err != nil {
		return Share{}, err
	}
	if len(shares) == 0 {
		return Share{}, ErrNotFound
	}
	return shares[0], nil
}

func (db *DB) Share(id string) (d Share, err error) {
	err = db.read(func(tx *sql.Tx) error { d, err = scanShare(tx, id, 0); return err })
	return
}

func (db *DB) ShareCapped(id string, maxFiles int) (d Share, err error) {
	err = db.read(func(tx *sql.Tx) error { d, err = scanShare(tx, id, maxFiles); return err })
	return
}

// SharesByID reads several shares in one read transaction, each with the same
// files window ShareCapped gives it (maxFiles <= 0 means
// DefaultMaxFilesPerShare). The page budget is the window times the number of
// shares, so no share's window shrinks for being read with others. An id that names
// no share is absent from the result, which is in first-seen id order with
// each id once.
func (db *DB) SharesByID(ids []string, maxFiles int) (shares []Share, err error) {
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFilesPerShare
	}
	seen := make(map[string]bool, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if shareid.ValidID(id) && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	err = db.read(func(tx *sql.Tx) error {
		shares, err = fetchPage(tx, unique, maxFiles, maxFiles*len(unique))
		return err
	})
	return
}

func validateCreate(o CreateOptions) error {
	if o.Owner == "" {
		return fmt.Errorf("%w: owner is required", ErrBadRequest)
	}
	if o.ID != "" && !shareid.ValidID(o.ID) {
		return fmt.Errorf("%w: invalid share id", ErrBadRequest)
	}
	if o.Entry != "" && !shareid.ValidRelPath(o.Entry) {
		return fmt.Errorf("%w: entry %q is not a relative path", ErrBadRequest, o.Entry)
	}
	answers := 0
	if o.Entry != "" {
		answers++
	}
	if o.Media {
		answers++
	}
	if o.Listing {
		answers++
	}
	if answers > 1 {
		return fmt.Errorf("%w: entry, media and listing are mutually exclusive", ErrBadRequest)
	}
	if o.Text {
		switch {
		case o.Inbox:
			return fmt.Errorf("%w: a share is a text share or an inbox, never both", ErrBadRequest)
		case answers > 0:
			return fmt.Errorf("%w: a text share opens as its file and takes no entry, gallery or listing", ErrBadRequest)
		case len(o.Sources) > 0:
			return fmt.Errorf("%w: a text share holds one uploaded file, never a server folder", ErrBadRequest)
		case len(o.Files) > 1:
			return fmt.Errorf("%w: a text share's manifest declares at most one file, not %d", ErrBadRequest, len(o.Files))
		}
	}
	seen := map[string]bool{}
	for _, f := range o.Files {
		if !shareid.ValidRelPath(f.Path) {
			return fmt.Errorf("%w: manifest path %q", ErrBadRequest, f.Path)
		}
		if f.Size < 0 {
			return fmt.Errorf("%w: manifest size for %q", ErrBadRequest, f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("%w: duplicate manifest path %q", ErrBadRequest, f.Path)
		}
		seen[f.Path] = true
	}
	return nil
}

// CreateShare inserts the share, its manifest rows and its sources, and
// records the change. The caller has already validated
// name length, source boundaries and the inbox defaults.
func (db *DB) CreateShare(o CreateOptions) (d Share, err error) {
	if err := validateCreate(o); err != nil {
		return Share{}, err
	}
	err = db.commit(func(tx *sql.Tx) error {
		if _, err := scanUser(tx, o.Owner); err != nil {
			return fmt.Errorf("%w: owner %q", ErrBadRequest, o.Owner)
		}
		id := o.ID
		if id == "" {
			id = shareid.NewID()
		} else {
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM shares WHERE id = ?`, id).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("%w: share %s exists", ErrConflict, id)
			}
		}
		now := time.Now()
		created := o.CreatedAt
		if created.IsZero() {
			created = now
		}
		pw := nullIfEmpty(o.PasswordHash)
		var sealed []byte
		if o.SealPassword != nil && o.PasswordHash != "" {
			var serr error
			if sealed, serr = o.SealPassword(id); serr != nil {
				return serr
			}
		}
		if _, err := tx.Exec(`INSERT INTO shares(id, owner, name, name_lower, folder, entry, media, listing, inbox, text, note,
			max_bytes, max_files, password_hash, password_sealed, created_at, expires_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, o.Owner, o.Name, searchKey(o.Name), o.Folder, o.Entry, o.Media, o.Listing, o.Inbox, o.Text, o.Note,
			o.MaxBytes, o.MaxFiles, pw, sealedOrNull(sealed, o.PasswordHash), toNS(created), toNSPtr(o.ExpiresAt)); err != nil {
			return err
		}
		for _, f := range o.Files {
			if err := insertPending(tx, id, f.Path, f.Size, now); err != nil {
				return err
			}
		}
		for i, s := range o.Sources {
			if _, err := tx.Exec(`INSERT INTO share_sources(share_id, source, position) VALUES(?, ?, ?)`, id, s, i); err != nil {
				return err
			}
		}
		if err := recordChange(tx, o.Owner, id, false, now); err != nil {
			return err
		}
		d, err = scanShare(tx, id, 0)
		return err
	})
	return
}

// searchKey is a share name as ?q= matches it (name_lower): lowered by Go's
// Unicode rules, the lowering List gives the query, so a capital outside
// ASCII matches as an ASCII one does. SQLite's lower() folds ASCII only.
func searchKey(name string) string { return strings.ToLower(name) }

// setName renames a share and its search key together.
func setName(tx *sql.Tx, id, name string) error {
	_, err := tx.Exec(`UPDATE shares SET name = ?, name_lower = ? WHERE id = ?`, name, searchKey(name), id)
	return err
}

// rekeyNames rewrites every search key that differs from searchKey(name),
// which a row keyed by SQLite's lower() holds when its name has a capital
// outside ASCII. Only a name holding a character outside printable ASCII can
// differ, and the GLOB picks those out inside SQLite, so a volume of ASCII
// names costs one scan and no row reaches Go. The serving open runs it on
// every boot, which re-keys any row a release keying with lower() wrote.
func rekeyNames(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id, name, name_lower FROM shares WHERE name GLOB '*[^ -~]*'`)
	if err != nil {
		return err
	}
	type stale struct{ id, name string }
	var out []stale
	err = eachRow(rows, func() error {
		var id, name, key string
		if err := rows.Scan(&id, &name, &key); err != nil {
			return err
		}
		if key != searchKey(name) {
			out = append(out, stale{id, name})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, r := range out {
		if err := setName(tx, r.id, r.name); err != nil {
			return err
		}
	}
	return nil
}

// UpdateOptions is one edit. A Set* flag says the field is present; the value
// beside it is what to write.
type UpdateOptions struct {
	SetPassword    bool
	PasswordHash   string // "" with SetPassword removes the password
	PasswordSealed []byte // the readable copy written with SetPassword, in the statement that writes the hash; nil = NULL
	SetExpiry      bool
	ExpiresAt      *time.Time // nil with SetExpiry = never
	SetName        bool
	Name           string // already validated by the API
	SetFolder      bool
	Folder         bool // whether the share reads as a folder rather than one file
	SetEntry       bool
	Entry          string // "" = back to the listing
	SetMedia       bool
	Media          bool
	SetListing     bool
	Listing        bool
	SetClosed      bool
	Closed         bool
	SetNote        bool
	Note           string
	SetNotify      bool
	Notify         bool       // true = announce; stored inverted
	SeenAt         *time.Time // kept only when later than the stored one
	SetPinned      bool
	Pinned         bool      // pinning an already pinned share keeps its pin time
	PinnedAt       time.Time // the pin time a new pin takes; zero = now
}

// Empty reports whether o carries no field at all, so a request that only
// cancels or only schedules writes no row.
func (o UpdateOptions) Empty() bool { return !o.editsFields() && o.SeenAt == nil && !o.SetPinned }

// editsFields reports whether o carries a field other than SeenAt and the
// pin. Reading a share is not an edit and neither is ordering the owner's
// own list, so an update carrying only those leaves modified_at alone.
func (o UpdateOptions) editsFields() bool {
	return o.SetPassword || o.SetExpiry || o.SetName || o.SetEntry || o.SetMedia || o.SetListing ||
		o.SetClosed || o.SetNote || o.SetNotify || o.SetFolder
}

// applyUpdate writes o onto the row inside tx. The opens-as CHECK constraint
// enforces one View answer on the resulting state; its failure is reported
// as ErrBadRequest. h is the share's head, read in the same transaction.
func applyUpdate(tx *sql.Tx, id string, h shareHead, o UpdateOptions, now time.Time) error {
	set := func(col string, v any) error {
		_, err := tx.Exec(`UPDATE shares SET `+col+` = ? WHERE id = ?`, v, id)
		return err
	}
	if o.SetName {
		if err := setName(tx, id, o.Name); err != nil {
			return err
		}
	}
	if o.SetPassword {
		pw := nullIfEmpty(o.PasswordHash)
		if _, err := tx.Exec(`UPDATE shares SET password_hash = ?, password_sealed = ?, password_gen = password_gen + 1 WHERE id = ?`,
			pw, sealedOrNull(o.PasswordSealed, o.PasswordHash), id); err != nil {
			return err
		}
		if err := cancelScheduled(tx, id, ScheduledPassword); err != nil {
			return err
		}
	}
	if o.SetExpiry {
		if err := set("expires_at", toNSPtr(o.ExpiresAt)); err != nil {
			return err
		}
		if err := cancelScheduled(tx, id, ScheduledExpiry); err != nil {
			return err
		}
	}
	if o.SetFolder {
		if err := set("folder", o.Folder); err != nil {
			return err
		}
	}
	if o.SetEntry && o.Entry != "" && !shareid.ValidRelPath(o.Entry) {
		return fmt.Errorf("%w: entry %q", ErrBadRequest, o.Entry)
	}
	if (o.SetEntry || o.SetMedia || o.SetListing) && h.text {
		return ErrTextShare
	}
	if err := setOpens(tx, id, o); err != nil {
		return checkErr(err)
	}
	if o.SetClosed {
		if err := set("closed", o.Closed); err != nil {
			return err
		}
	}
	if o.SetNote {
		if err := set("note", o.Note); err != nil {
			return err
		}
	}
	if o.SetNotify {
		if err := set("notify_off", !o.Notify); err != nil {
			return err
		}
	}
	if o.SeenAt != nil {
		if _, err := tx.Exec(`UPDATE shares SET seen_at = ? WHERE id = ? AND (seen_at IS NULL OR seen_at < ?)`, toNS(*o.SeenAt), id, toNS(*o.SeenAt)); err != nil {
			return err
		}
	}
	if o.SetPinned {
		pinned := `NULL`
		var args []any
		if o.Pinned {
			at := o.PinnedAt
			if at.IsZero() {
				at = now
			}
			pinned, args = `COALESCE(pinned_at, ?)`, []any{toNS(at)}
		}
		if _, err := tx.Exec(`UPDATE shares SET pinned_at = `+pinned+` WHERE id = ?`, append(args, id)...); err != nil {
			return err
		}
	}
	if !o.editsFields() {
		return nil
	}
	return touch(tx, id, now)
}

// setOpens writes whichever of entry, media and listing o carries, in ONE
// statement. The CHECK constraint is evaluated per statement, so writing them
// one at a time would refuse a swap of the View answer (listing to gallery,
// say) on the half-written row, although the state it asks for holds a single
// answer. Fields o leaves alone keep their stored value and are judged
// alongside the ones it sets.
func setOpens(tx *sql.Tx, id string, o UpdateOptions) error {
	var cols []string
	var args []any
	if o.SetEntry {
		cols, args = append(cols, "entry = ?"), append(args, o.Entry)
	}
	if o.SetMedia {
		cols, args = append(cols, "media = ?"), append(args, o.Media)
	}
	if o.SetListing {
		cols, args = append(cols, "listing = ?"), append(args, o.Listing)
	}
	if len(cols) == 0 {
		return nil
	}
	_, err := tx.Exec(`UPDATE shares SET `+strings.Join(cols, ", ")+` WHERE id = ?`, append(args, id)...)
	return err
}

// checkErr maps a CHECK constraint failure of setOpens' statement, which
// only the one-View-answer CHECK can refuse, to ErrBadRequest.
func checkErr(err error) error {
	if sqliteCode(err) == sqlite3.SQLITE_CONSTRAINT_CHECK {
		return fmt.Errorf("%w: entry, media and listing are mutually exclusive", ErrBadRequest)
	}
	return err
}

// updateShare writes o onto the share, records the change and reads the share
// back with editWindow file entries, all inside the caller's transaction.
// ApplyDue calls it too, so a due row is applied under the same rules as an
// immediate edit.
func updateShare(tx *sql.Tx, id string, o UpdateOptions, now time.Time) (Share, error) {
	h, err := readHead(tx, id)
	if err != nil {
		return Share{}, err
	}
	if err := applyUpdate(tx, id, h, o, now); err != nil {
		return Share{}, err
	}
	if err := recordChange(tx, h.owner, id, false, now); err != nil {
		return Share{}, err
	}
	return scanShare(tx, id, editWindow)
}

// UpdateShare applies one edit and answers the share with editWindow file
// entries.
func (db *DB) UpdateShare(id string, o UpdateOptions) (d Share, err error) {
	if o.Empty() {
		return Share{}, fmt.Errorf("%w: nothing to update", ErrBadRequest)
	}
	err = db.commit(func(tx *sql.Tx) error {
		var uerr error
		d, uerr = updateShare(tx, id, o, time.Now())
		return uerr
	})
	return
}

// Expired lists shares whose expiry has passed. The partial index makes this
// O(shares with an expiry).
func (db *DB) Expired(now time.Time) (ids []string, err error) {
	err = db.read(func(tx *sql.Tx) error {
		ids, err = queryStrings(tx, `SELECT id FROM shares WHERE expires_at IS NOT NULL AND expires_at < ? ORDER BY expires_at`, toNS(now))
		return err
	})
	return
}

// DeleteShare removes the share and everything under it in one statement and
// records the deletion. The caller removes the directory afterwards.
// ErrNotFound when there is no such share.
func (db *DB) DeleteShare(id string) error {
	deleted, err := db.deleteShareIf(id, `1`)
	if err == nil && !deleted {
		return ErrNotFound
	}
	return err
}
