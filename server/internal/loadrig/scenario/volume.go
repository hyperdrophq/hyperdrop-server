package scenario

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"hyperdrop/server/internal/loadrig/report"
	"hyperdrop/server/internal/loadrig/volume"
	"hyperdrop/server/internal/metadb"
)

// VolumeName is the pseudo-scenario every run records first: the volume's
// sizes on disk at the run's start and end. It is not one of All and is
// never skipped.
const VolumeName = "volume"

// The volume's values; RecordVolumeSizes appends " at start" or " at end"
// to the first two.
const (
	valDatabase      = "database file"
	valDatabaseLog   = "database -wal file"
	valGeneratedDisk = "disk used as generated"
	valGeneratedNode = "inodes used as generated"
)

// RecordVolumeSizes records the sizes of the database file in dir and of
// its write-ahead log, read now, under when ("at start", "at end"); and,
// with generated, the disk use and inodes the manifest says generating
// took. It reads two file sizes and walks nothing. A log that does not
// exist is one of no bytes; a database that cannot be read is not available,
// with the reason.
func RecordVolumeSizes(rec *report.Recorder, dir string, man volume.Manifest, when string, generated bool) {
	db := filepath.Join(dir, metadb.FileName)
	if fi, err := os.Stat(db); err != nil {
		why := "the database cannot be read: " + err.Error()
		rec.NotAvailable(valDatabase+" "+when, why)
		rec.NotAvailable(valDatabaseLog+" "+when, why)
	} else {
		rec.Value(valDatabase+" "+when, mib(fi.Size()), "MiB")
		switch wal, err := os.Stat(db + "-wal"); {
		case err == nil:
			rec.Value(valDatabaseLog+" "+when, mib(wal.Size()), "MiB")
		case errors.Is(err, fs.ErrNotExist):
			rec.Value(valDatabaseLog+" "+when, 0, "MiB")
		default:
			rec.NotAvailable(valDatabaseLog+" "+when, "the log cannot be read: "+err.Error())
		}
	}
	if !generated {
		return
	}
	if man.DiskBytes > 0 || man.Inodes > 0 {
		rec.Value(valGeneratedDisk, mib(man.DiskBytes), "MiB")
		rec.Value(valGeneratedNode, float64(man.Inodes), "inodes")
		return
	}
	why := "the generator could not measure the file system"
	rec.NotAvailable(valGeneratedDisk, why)
	rec.NotAvailable(valGeneratedNode, why)
}
