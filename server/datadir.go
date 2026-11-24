package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// dataNotWritableError is the one-sentence refusal of a data directory the
// server's user cannot write, naming the command that gives it to that user.
type dataNotWritableError struct {
	dir string
	uid int
}

func (e dataNotWritableError) Error() string {
	return fmt.Sprintf("the data directory %s is not writable by this server (uid %d); give it to that user: chown -R %d %s (on Docker: docker run --rm -v <volume>:/data alpine chown -R 10001:10001 /data)",
		e.dir, e.uid, e.uid, e.dir)
}

// checkDataWritable proves the server can create files in dir by creating and
// removing dir/.write-check. A missing dir is created first, mode 0700.
func checkDataWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return dataNotWritableError{dir: dir, uid: os.Geteuid()}
	}
	probe := filepath.Join(dir, ".write-check")
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return dataNotWritableError{dir: dir, uid: os.Geteuid()}
	}
	f.Close()
	if err := os.Remove(probe); err != nil {
		return dataNotWritableError{dir: dir, uid: os.Geteuid()}
	}
	return nil
}
