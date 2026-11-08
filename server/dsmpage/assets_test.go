package dsmpage

import (
	"strings"
	"testing"
)

// The page's script serves both DSM generations: it fetches its token with
// the query DSM 6 needs (DSM 7 answers it too), and draws the Storage tab
// read-only when the API says the data cannot move.
func TestPageScriptCarriesTheDSM6Words(t *testing.T) {
	js, err := assets.ReadFile("assets/page.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/webman/login.cgi?enable_syno_token=yes",
		"storage.movable === false",
		"beside the package",
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("page.js lacks %q", want)
		}
	}
	if strings.Contains(string(js), "fetch('/webman/login.cgi',") {
		t.Error("page.js still fetches the token without the query")
	}
}
