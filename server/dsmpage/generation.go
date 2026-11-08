package dsmpage

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The two DSM generations keep a package's files in different places. On
// DSM 7 the package has a var link (/var/packages/hyperdrop/var, into
// @appdata) and its data lives in a shared folder DSM links under the
// package's shares directory. DSM 6 has no var link: the conf, the status
// file and the data (its data/ folder) all live in @appdata/hyperdrop on
// the volume the package is installed on, which only the target link
// (/var/packages/hyperdrop/target -> /volumeN/@appstore/hyperdrop) names.
// scripts/common follows the same rule (data_dir, data_path).

// versionFile is where DSM records its own version.
const versionFile = "/etc.defaults/VERSION"

// readMajor answers the DSM generation the version file names, and 7 for a
// file it cannot read or parse: the layout the defaults describe.
func readMajor(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 7
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "majorversion="); ok {
			if strings.Trim(v, `"`) == "6" {
				return 6
			}
			return 7
		}
	}
	return 7
}

// volumePrefix matches the volume directory a DSM path lives on.
var volumePrefix = regexp.MustCompile(`^(.*?/volume[0-9]+)/`)

// dsm6VarDir answers the package's var directory on DSM 6, @appdata on the
// volume the target link resolves to, and "" when the link does not resolve
// or resolves to no volume.
func dsm6VarDir(target string) string {
	dest, err := filepath.EvalSymlinks(target)
	if err != nil {
		return ""
	}
	m := volumePrefix.FindStringSubmatch(dest)
	if m == nil {
		return ""
	}
	return m[1] + "/@appdata/hyperdrop"
}

// dsm6 answers whether the page runs on DSM 6.
func (p *page) dsm6() bool { return p.deps.Major == 6 }
