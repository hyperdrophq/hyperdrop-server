package metadb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// integrityScanKey is the meta row holding the last integrity scan that
// finished, as {"at":<unix ns>,"files":<n>,"missing":<m>}.
const integrityScanKey = "integrity_scan"

// IntegrityScan is one finished integrity scan: when it started, how many
// stored files it checked and how many of them it found missing from disk.
type IntegrityScan struct {
	At             time.Time
	Files, Missing int
}

type integrityScanJSON struct {
	At      int64 `json:"at"`
	Files   int   `json:"files"`
	Missing int   `json:"missing"`
}

// LastIntegrityScan answers the last recorded integrity scan; ok is false
// when none was recorded or the stored value does not read, either of which
// owes a scan.
func (db *DB) LastIntegrityScan() (s IntegrityScan, ok bool, err error) {
	var raw string
	err = db.read(func(tx *sql.Tx) error {
		err := tx.QueryRow(`SELECT value FROM meta WHERE key = ?`, integrityScanKey).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil || !ok {
		return IntegrityScan{}, false, err
	}
	var j integrityScanJSON
	if json.Unmarshal([]byte(raw), &j) != nil || j.At <= 0 {
		return IntegrityScan{}, false, nil
	}
	return IntegrityScan{At: time.Unix(0, j.At), Files: j.Files, Missing: j.Missing}, true, nil
}

// RecordIntegrityScan stores s as the last integrity scan, replacing the
// one before. It is not share state and wakes no Subscribe.
func (db *DB) RecordIntegrityScan(s IntegrityScan) error {
	raw, err := json.Marshal(integrityScanJSON{At: s.At.UnixNano(), Files: s.Files, Missing: s.Missing})
	if err != nil {
		return err
	}
	return db.write(func(tx *sql.Tx) error { return setMeta(tx, integrityScanKey, string(raw)) })
}
