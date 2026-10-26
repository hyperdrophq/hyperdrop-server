package api

import (
	"strings"
	"testing"
)

func TestTheIconCarriesNoScript(t *testing.T) {
	if strings.Contains(strings.ToLower(string(iconSVG)), "<script") {
		t.Fatal("the icon carries a script")
	}
}
