package dsmpage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every help link the DSM page, the wizards and the package scripts print
// names an anchor on the website's Synology page. The website tree is absent
// from the exported open-source tree, where the test skips.
func TestEveryPrintedHelpAnchorExistsOnTheSynologyPage(t *testing.T) {
	page, err := os.ReadFile("../../website/docs/synology/index.html")
	if err != nil {
		t.Skip("no website tree in this checkout")
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bid="([^"]+)"`).FindAllStringSubmatch(string(page), -1) {
		ids[m[1]] = true
	}

	// Where each source spells an anchor: a full address, the page's HELP
	// prefix, or the anchor argument of a message or hint.
	full := regexp.MustCompile(`docs/synology/#([a-z][a-z0-9-]*)`)
	helpJS := regexp.MustCompile(`HELP \+ '([a-z][a-z0-9-]*)'`)
	hintJS := regexp.MustCompile(`hint\([^\n]*?, '([a-z][a-z0-9-]*)'\)`)
	docsGo := regexp.MustCompile(`docsBase ?\+ ?"([a-z][a-z0-9-]*)"`)
	addGo := regexp.MustCompile(`, "([a-z][a-z0-9-]*)", (?:nil|&Action)`)

	roots := []string{".", "../../platforms/synology", "../../servermanagement/flow"}
	found := map[string]string{}
	for _, root := range roots {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(strings.ToLower(path), ".png") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			text := string(b)
			res := []*regexp.Regexp{full}
			switch {
			case strings.HasSuffix(path, ".js"):
				res = append(res, helpJS, hintJS)
			case strings.HasSuffix(path, ".go"):
				res = append(res, docsGo, addGo)
			}
			for _, re := range res {
				for _, m := range re.FindAllStringSubmatch(text, -1) {
					found[m[1]] = path
				}
			}
			return nil
		})
	}
	if len(found) == 0 {
		t.Fatal("found no help anchors: the patterns have drifted from the sources")
	}
	for anchor, path := range found {
		if !ids[anchor] {
			t.Errorf("%s prints docs/synology/#%s, but website/docs/synology/index.html has no id=%q", path, anchor, anchor)
		}
	}
	// Anchors the server, the wizards and the DSM page name through data
	// the patterns cannot see must exist too.
	for _, anchor := range []string{"ports", "settings-page", "proxy-header", "missing-files", "locked-folder", "move-storage", "admin-rescue", "firewall", "terminal", "wizard", "install"} {
		if !ids[anchor] {
			t.Errorf("website/docs/synology/index.html has no id=%q", anchor)
		}
	}
}
