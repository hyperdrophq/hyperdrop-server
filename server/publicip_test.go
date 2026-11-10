package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The public-IPv4 predicate exists twice (here and core/ipaddr) and
// can't share code: each copy runs the shared vectors so a divergent edit
// fails its module's tests. The server reads its own copy,
// server/testdata/public-ipv4.json, which the public server tree carries;
// TestThePublicIPv4VectorsAreTheSharedOnes (a monorepo test) fails when it
// differs from the repository's testdata/public-ipv4.json.
func TestIsPublicIPv4SharedVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "public-ipv4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		IP     string `json:"ip"`
		Public bool   `json:"public"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty vector file")
	}
	for _, c := range cases {
		if got := isPublicIPv4(c.IP); got != c.Public {
			t.Errorf("isPublicIPv4(%q) = %v, want %v", c.IP, got, c.Public)
		}
	}
}
