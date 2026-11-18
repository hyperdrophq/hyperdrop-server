package volume

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"hyperdrop/server/internal/fsatomic"
	"hyperdrop/server/internal/metadb"
)

// MarkerName is the generator's marker and manifest inside a volume's data
// directory. A directory holding it was created by the generator; nothing
// else in the server reads or writes it.
const MarkerName = "loadrig-volume.json"

// Password is the password every generated account signs in with.
const Password = "loadrig-account-password"

// SharePassword opens every password-protected share of a generated volume.
const SharePassword = "loadrig-share-password"

var (
	// ErrNotOurs refuses a directory that holds something other than a
	// generated volume: it has no marker.
	ErrNotOurs = errors.New("not a load-test volume")
	// ErrIncomplete is a volume whose generation did not finish.
	ErrIncomplete = errors.New("load-test volume is incomplete")
	// ErrExists refuses generating into a directory that already holds a
	// complete volume.
	ErrExists = errors.New("load-test volume already exists")
)

// Manifest is what the marker records about a volume. It is written with
// Complete false before anything else and rewritten with Complete true as
// the generator's last act, so a volume whose generation stopped reads as
// incomplete.
type Manifest struct {
	Plan     Plan
	Complete bool
	// ServerVersion is what wrote the rows: the metadb schema stamp and,
	// when the build carries it, the commit it was built from.
	ServerVersion string
	Accounts      []Account
	// Shares and Files are the rows the finished database holds.
	Shares, Files int64
	// DiskBytes and Inodes are what generating took from the file system,
	// measured as the change in its free blocks and inodes; other writers
	// on the same file system add to them.
	DiskBytes int64
	Inodes    int64
	Took      time.Duration
}

// Account is one generated account. Token is a raw bearer token minted for
// it; Shares is how many shares it owns.
type Account struct {
	Name, Token string
	Shares      int
}

func markerPath(dir string) string { return filepath.Join(dir, MarkerName) }

// readMarker reads the marker as it stands, complete or not.
func readMarker(dir string) (Manifest, error) {
	b, err := os.ReadFile(markerPath(dir))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", markerPath(dir), err)
	}
	return m, nil
}

// writeMarker replaces the marker durably. It holds bearer tokens, so it is
// readable by its owner alone.
func writeMarker(dir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.Write(markerPath(dir), b)
}

// ReadManifest answers the manifest of a complete volume: ErrNotOurs when
// dir holds no marker, ErrIncomplete when its generation did not finish.
func ReadManifest(dir string) (Manifest, error) {
	m, err := readMarker(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Manifest{}, fmt.Errorf("%w: %s has no %s", ErrNotOurs, dir, MarkerName)
	case err != nil:
		return Manifest{}, incomplete(dir)
	case !m.Complete:
		return Manifest{}, incomplete(dir)
	}
	return m, nil
}

func incomplete(dir string) error {
	return fmt.Errorf("%w: generating %s did not finish; remove that directory by hand and generate again", ErrIncomplete, dir)
}

// claim makes dir the generator's to write: a directory that does not exist
// is created, an empty one is taken as it is. Anything else is refused
// before a byte in it changes: a directory without the marker is not ours,
// one whose marker is incomplete was interrupted, one whose marker is
// complete already holds a volume.
func claim(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	case len(entries) == 0:
		return nil
	}
	m, err := readMarker(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s is not empty and has no %s", ErrNotOurs, dir, MarkerName)
	case err != nil, !m.Complete:
		return incomplete(dir)
	}
	return fmt.Errorf("%w: %s", ErrExists, dir)
}

// buildVersion names what writes a volume: the schema stamp, and the commit
// when the build records one.
func buildVersion() string {
	v := fmt.Sprintf("schema %d", metadb.SchemaVersion)
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return v
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if modified == "true" {
		rev += "+modified"
	}
	return v + ", " + rev
}
