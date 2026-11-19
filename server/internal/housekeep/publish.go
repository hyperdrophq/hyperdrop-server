package housekeep

import (
	"errors"
	"fmt"

	"hyperdrop/server/internal/metadb"
	"hyperdrop/server/internal/sharefs"
)

// FinishPublishes settles every commit journal the boot pass found in an
// open publish (sharefs.Journals), a commit a crash or a failed rename
// stopped. It runs in main's boot sequence after Orphans and before the
// listener starts, so no request sees a half-moved publish. Each journal
// is judged under the commit's own locks (sharefs.FinishPublish): one
// marked with its rows always rolls forward, path by path
// (markedVerdict); an unmarked one, a crash before the transaction or
// inside it, rolls forward when the rows already name the publish
// (publishVerdict) and is otherwise dropped, leaving the publish open to
// be committed again. A journal it cannot judge stays: a marked one for
// the housekeeping pass (RetryPublishes), an unmarked one for the next
// boot.
// It answers how many commits it finished and how many publishes it
// reopened.
func FinishPublishes(db *metadb.DB, fs *sharefs.FS) (finished, reopened int, err error) {
	journals, err := fs.Journals()
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, s := range journals {
		forward, err := fs.FinishPublish(s.ShareID, s.PID, s.Journal, func(j sharefs.Journal) (sharefs.JournalDecision, error) {
			if j.Rows != nil {
				return markedVerdict(db, fs, s.ShareID, s.PID, *j.Rows)
			}
			return publishVerdict(db, fs, s.ShareID, s.PID, j)
		})
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s/%s: %w", s.ShareID, s.PID, err))
		case forward:
			finished++
		default:
			reopened++
		}
	}
	return finished, reopened, errors.Join(errs...)
}

// errJournalSettled answers RetryPublishes' verdict for a journal that is
// gone or unmarked once its locks are held: nothing for the pass to do.
var errJournalSettled = errors.New("the journal is settled")

// RetryPublishes finishes, on a running server, every commit whose rows are
// written and whose renames failed: each open publish whose journal
// carries the rows mark is settled as the boot pass settles it
// (sharefs.FinishPublish, under the commit's own locks, markedVerdict
// path by path). A journal without the mark is a commit still running, or
// one only the boot pass can judge, and is left alone; the mark is read
// again under the locks, so a commit finished meanwhile is not counted. A
// rename that fails again leaves the journal for the next pass. It answers
// how many commits it finished.
func RetryPublishes(db *metadb.DB, fs *sharefs.FS) (int, error) {
	journals, err := fs.Journals()
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	finished := 0
	for _, s := range journals {
		if s.Journal.Rows == nil {
			continue
		}
		forward, err := fs.FinishPublish(s.ShareID, s.PID, s.Journal, func(sharefs.Journal) (sharefs.JournalDecision, error) {
			j, held, err := fs.ReadJournal(s.ShareID, s.PID)
			switch {
			case errors.Is(err, sharefs.ErrNotFound):
				return sharefs.JournalDecision{}, errJournalSettled
			case err != nil:
				return sharefs.JournalDecision{}, err
			case !held || j.Rows == nil:
				return sharefs.JournalDecision{}, errJournalSettled
			}
			return markedVerdict(db, fs, s.ShareID, s.PID, *j.Rows)
		})
		switch {
		case errors.Is(err, errJournalSettled):
		case err != nil:
			errs = append(errs, fmt.Errorf("%s/%s: %w", s.ShareID, s.PID, err))
		case forward:
			finished++
		}
	}
	return finished, errors.Join(errs...)
}

// publishVerdict decides whether the rows already name publish pid's
// commit j, which is true only after its transaction: every path j makes
// live has a committed row (looked up by the share's spelling of it) whose
// size and sha256 are the staged part's (or, its part already renamed,
// whose size the stored file has), and every path j deletes has no row. A
// journal naming nothing is never rolled forward. A read that fails is an
// error, so the journal stays.
func publishVerdict(db *metadb.DB, fs *sharefs.FS, id, pid string, j sharefs.Journal) (sharefs.JournalDecision, error) {
	var d sharefs.JournalDecision
	if len(j.Files)+len(j.Delete) == 0 {
		return d, nil
	}
	for _, p := range j.Files {
		to, err := db.Spelling(id, p, "")
		if err != nil {
			return d, err
		}
		row, err := db.File(id, to)
		if errors.Is(err, metadb.ErrNotFound) {
			return sharefs.JournalDecision{}, nil
		}
		if err != nil {
			return d, err
		}
		if row.Pending {
			return sharefs.JournalDecision{}, nil
		}
		if s, ok := fs.StagedFile(id, pid, p); ok {
			if s.SHA256 != row.SHA256 || s.Size != row.Size {
				return sharefs.JournalDecision{}, nil
			}
		} else if !fs.StagedGone(id, pid, p) {
			return sharefs.JournalDecision{}, nil
		} else if fi, err := fs.Stat(id, to); err != nil || fi.Size() != row.Size {
			return sharefs.JournalDecision{}, nil
		}
		d.Renames = append(d.Renames, sharefs.Rename{From: p, To: to})
	}
	for _, p := range j.Delete {
		spelled, err := db.Spelling(id, p, "")
		if err != nil {
			return d, err
		}
		if _, err := db.File(id, spelled); err == nil {
			return sharefs.JournalDecision{}, nil
		} else if !errors.Is(err, metadb.ErrNotFound) {
			return d, err
		}
		d.Removes = append(d.Removes, spelled)
	}
	d.Forward = true
	return d, nil
}

// markedVerdict finishes a commit whose transaction wrote its rows, as
// the journal's rows mark records them, path by path: writes may have
// landed on those paths since (a rename failed on a running server, and
// the paths were open to uploads and other commits until the housekeeping
// pass or a restart finished it).
// A staged part is renamed to its row's relpath only where that row still
// carries the part's size and sha256; elsewhere a later write superseded
// it, and it goes with the stage. A part already renamed needs nothing. A
// deleted path's bytes are removed only where no row stands at that path
// now (looked up under the share's spelling, so a later upload under
// another case keeps its bytes on a volume that folds case) and a stored
// file is still there (a later upload may have made the path a folder). A
// read of the database that fails is an error, so the journal stays.
func markedVerdict(db *metadb.DB, fs *sharefs.FS, id, pid string, rows sharefs.JournalRows) (sharefs.JournalDecision, error) {
	d := sharefs.JournalDecision{Forward: true}
	for _, rn := range rows.Renames {
		s, staged := fs.StagedFile(id, pid, rn.From)
		if !staged {
			continue
		}
		row, err := db.File(id, rn.To)
		if errors.Is(err, metadb.ErrNotFound) {
			continue
		}
		if err != nil {
			return sharefs.JournalDecision{}, err
		}
		if !row.Pending && row.SHA256 == s.SHA256 && row.Size == s.Size {
			d.Renames = append(d.Renames, rn)
		}
	}
	for _, p := range rows.Deleted {
		spelled, err := db.Spelling(id, p, "")
		if err != nil {
			return sharefs.JournalDecision{}, err
		}
		if _, err := db.File(id, spelled); err == nil {
			continue
		} else if !errors.Is(err, metadb.ErrNotFound) {
			return sharefs.JournalDecision{}, err
		}
		if _, err := fs.Stat(id, p); err != nil {
			continue
		}
		d.Removes = append(d.Removes, p)
	}
	return d, nil
}
