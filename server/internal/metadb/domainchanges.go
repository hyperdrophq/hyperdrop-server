package metadb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"hyperdrop/core/domainconn"
)

// domainChangesSetting is the settings row holding the server's recent
// address changes as a JSON list, oldest first.
const domainChangesSetting = "domainChanges"

// RecordDomainChange appends c to the remembered address changes in one
// transaction, dropping the ones older than domainconn.ChangeShownFor and
// keeping the newest domainconn.ChangesKept. An unreadable stored value
// starts the list afresh.
func (db *DB) RecordDomainChange(c domainconn.Change, now time.Time) error {
	return db.write(func(tx *sql.Tx) error {
		var raw string
		err := tx.QueryRow(`SELECT value FROM meta WHERE key = ?`, settingPrefix+domainChangesSetting).Scan(&raw)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		list := decodeDomainChanges(raw)
		out, err := json.Marshal(domainconn.RecordChange(list, c, now))
		if err != nil {
			return err
		}
		return setMeta(tx, settingPrefix+domainChangesSetting, string(out))
	})
}

// DomainChanges answers the remembered address changes younger than
// domainconn.ChangeShownFor, oldest first. A missing or unreadable value
// reads as none.
func (db *DB) DomainChanges(now time.Time) ([]domainconn.Change, error) {
	raw, ok, err := db.Setting(domainChangesSetting)
	if err != nil || !ok {
		return nil, err
	}
	return domainconn.ChangesShown(decodeDomainChanges(raw), now), nil
}

func decodeDomainChanges(raw string) []domainconn.Change {
	var list []domainconn.Change
	if raw == "" || json.Unmarshal([]byte(raw), &list) != nil {
		return nil
	}
	return list
}
