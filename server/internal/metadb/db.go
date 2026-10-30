package metadb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"hyperdrop/server/internal/shareid"
	"hyperdrop/server/internal/volsecret"
)

// FileName is the database's name inside the data directory.
const FileName = "hyperdrop.db"

// DB is an open metadata store.
type DB struct {
	w *sql.DB // one connection; every write transaction starts BEGIN IMMEDIATE
	r *sql.DB // read pool

	// totpKey seals and opens second-factor secrets (totpseal.go), and
	// recoveryKey keys recovery codes (twofactor.go); both nil on a database
	// opened as is.
	totpKey     *volsecret.Key
	recoveryKey []byte

	// writes counts the write transactions opened, so a test can prove a
	// read path takes the write lock only when it has something to write.
	writes atomic.Int64

	// sameName is set when the data volume folds case: it answers whether
	// the volume takes two relpaths of a share for one entry (casefold.go).
	sameName atomic.Pointer[func(shareID, held, incoming string) bool]

	subMu sync.Mutex
	subs  map[chan struct{}]struct{}
}

// fileURI is path as the file: URI SQLite opens. The path is escaped, so a
// ? or # in a directory name cannot end the path early and carry the
// pragmas after it away with what follows.
func fileURI(path string) string {
	return "file:" + strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
}

func dsn(path string, immediate bool) string {
	s := fileURI(path) + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	if immediate {
		s += "&_txlock=immediate"
	}
	return s
}

// Open opens or creates <dataDir>/hyperdrop.db, checks it and replaces a
// damaged file with the newest good backup. It reads the volume secret,
// creating it on a fresh volume, and seals every second-factor secret a row
// holds in plaintext (totpseal.go). It is what the serving process calls.
func Open(dataDir string) (*DB, error) { return open(dataDir, true) }

// OpenAsIs opens the database without the integrity-and-recover pass and
// without the volume secret, so it seals nothing. The
// operator subcommands (checkschema, checkdb, admins, resetadmin, reset2fa)
// use it because the provisioner runs them while the previous server still
// serves the volume, and a recovery under a serving process would race it.
func OpenAsIs(dataDir string) (*DB, error) { return open(dataDir, false) }

func open(dataDir string, serving bool) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	var totpKey *volsecret.Key
	var recoveryKey []byte
	if serving {
		var err error
		if totpKey, recoveryKey, err = volumeKeys(dataDir); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(dataDir, FileName)
	// The serving process checks the file before it opens it, and a file
	// that fails is replaced by the newest good backup (backup.go). The
	// operator subcommands open the volume as it is: another server may be
	// serving it.
	recovered := false
	if serving {
		if err := quickCheck(path); err != nil {
			log.Printf("database: %v", err)
			if !errors.Is(err, errCorrupt) {
				return nil, err
			}
			if err := recoverDatabase(dataDir, time.Now()); err != nil {
				return nil, err
			}
			recovered = true
		}
	}
	if err := createOwnerOnly(path); err != nil {
		return nil, err
	}
	w, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		_ = w.Close() // the open's own error is the one the caller needs
		return nil, err
	}
	// Idle read connections stay open up to the pool's size: one closed
	// after each use reopens with the DSN's pragmas and parses the schema
	// again.
	r.SetMaxOpenConns(8)
	r.SetMaxIdleConns(8)
	db := &DB{w: w, r: r, totpKey: totpKey, recoveryKey: recoveryKey, subs: map[chan struct{}]struct{}{}}
	sealed, keyed, err := db.ensureSchema(serving)
	if err != nil {
		_ = db.Close() // the schema's error is the one the caller needs
		return nil, err
	}
	if sealed > 0 {
		log.Printf("database: sealed %d second-factor secrets", sealed)
	}
	if keyed > 0 {
		log.Printf("database: keyed %d recovery codes", keyed)
	}
	if sealed > 0 || keyed > 0 {
		db.scrubFreedPages()
	}
	if recovered {
		if err := db.forgetJournal(time.Now()); err != nil {
			_ = db.Close() // the journal's error is the one the caller needs
			return nil, err
		}
	}
	return db, nil
}

// createOwnerOnly creates path as an empty owner-only file when nothing is
// there yet. SQLite reads an empty file as a new database and gives the -wal
// and -shm files it creates the database's own mode, so the password hashes,
// second-factor secrets and token hashes the store holds are readable by the
// service account alone, whatever umask the process runs under.
func createOwnerOnly(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

// ensureSchema stamps an empty database with the whole schema and accepts a
// database at SchemaVersion and, when serving, adds the additive columns a
// volume made by an earlier release of this stamp lacks (additive.go) and
// re-keys the share names an earlier release keyed (rekeyNames) and the
// file and folder rows whose fold_key is missing or stale (rekeyFolds),
// seals the second-factor secrets a row holds in plaintext (sealPlainTOTP)
// and keys the recovery codes a row holds as plain hashes
// (rekeyRecoveryCodes), answering how many it sealed and keyed. Any other stamp is refused: a higher one was
// written by a newer server, and a stamp-0 file that already holds tables is
// not ours. Serving, it builds FoldPath's table first, which every write
// that sets a path reads.
func (db *DB) ensureSchema(serving bool) (sealed, keyed int, err error) {
	if serving {
		shareid.PrepareFold()
	}
	err = db.write(func(tx *sql.Tx) error {
		var v int
		if err := tx.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
			return err
		}
		switch {
		case v == SchemaVersion:
			if !serving {
				return nil
			}
			if err := ensureAdditive(tx); err != nil {
				return err
			}
			if err := rekeyNames(tx); err != nil {
				return err
			}
			if err := rekeyFolds(tx); err != nil {
				return err
			}
			if sealed, err = sealPlainTOTP(tx, db.totpKey); err != nil {
				return err
			}
			keyed, err = rekeyRecoveryCodes(tx, db.recoveryKey)
			return err
		case v > SchemaVersion:
			return fmt.Errorf("%w (stamp %d)", ErrSchemaTooNew, v)
		case v < 0:
			return fmt.Errorf("%w (stamp %d)", ErrSchemaUnknown, v)
		}
		var objects int
		if err := tx.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`).Scan(&objects); err != nil {
			return err
		}
		if objects != 0 {
			return fmt.Errorf("%w (stamp 0, %d objects)", ErrSchemaUnknown, objects)
		}
		if _, err := tx.Exec(schemaSQL); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		return stamp(tx, SchemaVersion)
	})
	return sealed, keyed, err
}

func stamp(tx *sql.Tx, v int) error {
	_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v))
	return err
}

// Close closes both handles. The last connection to close checkpoints the WAL.
func (db *DB) Close() error {
	return errors.Join(db.r.Close(), db.w.Close())
}

// write runs fn in one immediate transaction on the write connection.
func (db *DB) write(fn func(tx *sql.Tx) error) error {
	db.writes.Add(1)
	tx, err := db.w.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// read runs fn in one deferred (read) transaction so several statements see
// one snapshot.
func (db *DB) read(fn func(tx *sql.Tx) error) error {
	tx, err := db.r.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(tx)
}

// eachRow calls fn once per row of rows, fn scanning the current row itself,
// and closes rows whatever happens. It answers fn's first error, which stops
// the iteration, or else the error the iteration itself left behind.
func eachRow(rows *sql.Rows, fn func() error) error {
	defer rows.Close()
	for rows.Next() {
		if err := fn(); err != nil {
			return err
		}
	}
	return rows.Err()
}

// queryStrings runs a query answering one string column and drains it.
func queryStrings(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	return scanStrings(rows)
}

// scanStrings drains a one-column string result.
func scanStrings(rows *sql.Rows) ([]string, error) {
	var out []string
	err := eachRow(rows, func() error {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		out = append(out, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Subscribe returns a channel that receives one value after any commit that
// changed shares, and a cancel func. Wakes coalesce: a subscriber that has not
// drained its channel gets one pending wake, and the writer never blocks.
func (db *DB) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	db.subMu.Lock()
	db.subs[ch] = struct{}{}
	db.subMu.Unlock()
	return ch, func() {
		db.subMu.Lock()
		delete(db.subs, ch)
		db.subMu.Unlock()
	}
}

func (db *DB) notify() {
	db.subMu.Lock()
	defer db.subMu.Unlock()
	for ch := range db.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
