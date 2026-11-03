// Package conffile edits the Synology package's hyperdrop.conf the way the
// package's own conf_set does (platforms/synology/scripts/common), so the
// server, the DSM page and the package scripts write one format: one
// KEY=value line per key, the proxy list and the shared folder's name in
// double quotes, every other value bare. The start script SOURCES the conf,
// so callers validate a value before it is written; nothing here does.
//
// It also writes the package's other small state files: Write is the one
// atomic, mode-0600 replace they all go through.
package conffile

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Limit bounds how much of the conf is read: a few short lines.
const Limit = 64 << 10

// errNotPlain refuses a conf that is a link, a hard link or not a file.
var errNotPlain = errors.New("the conf is not a plain file")

// quoted are the keys, without their HYPERDROP_ prefix, whose values may
// hold spaces and are written in double quotes.
var quoted = []string{"TRUSTED_PROXIES", "SHARED_FOLDER"}

// Line is the conf line for key and value.
func Line(key, value string) string {
	if name, ok := strings.CutPrefix(key, "HYPERDROP_"); ok && slices.Contains(quoted, name) {
		return key + `="` + value + `"`
	}
	return key + "=" + value
}

// SetText is conf_set on the conf's text: the first line starting with key=
// is replaced by Line(key, value), later ones are dropped, the line is
// appended when absent, and every other line is kept byte for byte. Each
// line ends in a newline.
func SetText(text, key, value string) string {
	var b strings.Builder
	done := false
	if text != "" {
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if strings.HasPrefix(line, key+"=") {
				if !done {
					b.WriteString(Line(key, value) + "\n")
				}
				done = true
				continue
			}
			b.WriteString(line + "\n")
		}
	}
	if !done {
		b.WriteString(Line(key, value) + "\n")
	}
	return b.String()
}

// Read answers the conf's text. The conf is read only when it is a regular
// file with one link and at most Limit bytes, and no link is followed.
func Read(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !plain(fi) {
		return "", errNotPlain
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if ofi, err := f.Stat(); err != nil || !plain(ofi) || !os.SameFile(fi, ofi) {
		return "", errNotPlain
	}
	b, err := io.ReadAll(io.LimitReader(f, Limit+1))
	if err != nil {
		return "", err
	}
	if len(b) > Limit {
		return "", errors.New("the conf is too large")
	}
	return string(b), nil
}

func plain(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return fi.Mode().IsRegular() && (!ok || st.Nlink == 1)
}

// Write replaces path with text, mode 0600: the text goes to a new file
// beside it, which is synced and renamed over path, so a failure leaves the
// old file as it was and a link planted at path is replaced, never followed.
func Write(path, text string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(text)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr, os.Chmod(tmp.Name(), 0o600)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Edit reads the conf at path, applies edit to its text and writes the
// result when it differs.
func Edit(path string, edit func(string) string) error {
	text, err := Read(path)
	if err != nil {
		return err
	}
	next := edit(text)
	if next == text {
		return nil
	}
	return Write(path, next)
}

// Set is conf_set KEY VALUE on the conf at path.
func Set(path, key, value string) error {
	return Edit(path, func(text string) string { return SetText(text, key, value) })
}

// ParseTrustedProxies parses HYPERDROP_TRUSTED_PROXIES: a comma-separated
// list of addresses and CIDR prefixes, spaces tolerated. Empty means none. An
// IPv4-mapped IPv6 entry is normalised to IPv4, the form a peer is matched
// in. A malformed entry, or a catch-all that trusts every address on the
// internet, is an error naming it: an unnoticed typo would silently leave the
// lockout shared, and a catch-all lets anyone forge an address.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(entry, "/") {
			pp, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("HYPERDROP_TRUSTED_PROXIES entry %q is not an address or CIDR prefix", entry)
			}
			if a := pp.Addr(); a.Is4In6() && pp.Bits() >= 96 {
				pp = netip.PrefixFrom(a.Unmap(), pp.Bits()-96)
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(entry)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("HYPERDROP_TRUSTED_PROXIES entry %q is not an address or CIDR prefix", entry)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("HYPERDROP_TRUSTED_PROXIES entry %q trusts every address on the internet: "+
				"list the proxy's own address instead", entry)
		}
		out = append(out, p)
	}
	return out, nil
}
