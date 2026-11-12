package api

import (
	"strings"
	"testing"

	"hyperdrop/core/sharenamerule"
)

// The server refuses what the clients refuse, through the same rule.
func TestCleanShareNameIsTheClientsRule(t *testing.T) {
	got, err := cleanShareName("  Q3 Financials  ")
	if err != nil || got != "Q3 Financials" {
		t.Errorf("cleanShareName = %q, %v; want %q, nil", got, err, "Q3 Financials")
	}
	for _, bad := range []string{
		"", "   ", "a/b", "a\nb", "a\x7fb",
		strings.Repeat("x", sharenamerule.MaxLen+1),
	} {
		if _, err := cleanShareName(bad); err == nil {
			t.Errorf("cleanShareName(%q) = nil error, want a refusal", bad)
		}
	}
}
