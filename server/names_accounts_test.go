package main

import "testing"

func TestCertSubjectsCoverTheAppDomainAndTheIPOnly(t *testing.T) {
	subjects := initialCertSubjects("alice.hyperdrop.link", "203.0.113.7", false)
	want := []string{"alice.hyperdrop.link", "203.0.113.7"}
	if len(subjects) != len(want) {
		t.Fatalf("subjects %v, want %v", subjects, want)
	}
	for i := range want {
		if subjects[i] != want[i] {
			t.Fatalf("subjects %v, want %v", subjects, want)
		}
	}
}

// The file origin is served from the app domain's certificate, so managing it
// would order the second certificate this change exists to avoid.
func TestTheFileOriginIsNeverManaged(t *testing.T) {
	for _, s := range initialCertSubjects("alice.hyperdrop.link", "203.0.113.7", false) {
		if s == "files.alice.hyperdrop.link" {
			t.Fatal("files.alice.hyperdrop.link is managed separately")
		}
	}
}

// A certificate carrying the app domain by itself serves no file origin, and
// nothing in certificate management inspects which names a stored certificate
// carries, so the server decides that for itself at boot. A certificate that
// already carries the file origin is left alone: forcing a renewal on every
// restart would spend the weekly certificate budget a boot at a time.
func TestAForcedRenewalIsOwedOnlyWhenTheFileOriginIsMissing(t *testing.T) {
	for _, tc := range []struct {
		label      string
		names      []string
		fileOrigin string
		want       bool
	}{
		{"the app domain alone", []string{"alice.hyperdrop.link"}, "files.alice.hyperdrop.link", true},
		{"both names", []string{"alice.hyperdrop.link", "files.alice.hyperdrop.link"}, "files.alice.hyperdrop.link", false},
		{"both names, file origin first", []string{"files.alice.hyperdrop.link", "alice.hyperdrop.link"}, "files.alice.hyperdrop.link", false},
		{"a differently cased file origin", []string{"alice.hyperdrop.link", "Files.Alice.Hyperdrop.Link"}, "files.alice.hyperdrop.link", false},
		{"another server's pair", []string{"bob.hyperdrop.link", "files.bob.hyperdrop.link"}, "files.alice.hyperdrop.link", true},
		{"no names at all", nil, "files.alice.hyperdrop.link", true},
		{"no file origin to want", []string{"203.0.113.7"}, "", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := pairedCertificateOwed(tc.names, tc.fileOrigin); got != tc.want {
				t.Fatalf("pairedCertificateOwed(%v, %q) = %v, want %v", tc.names, tc.fileOrigin, got, tc.want)
			}
		})
	}
}

func TestAPendingFreeNameManagesTheIPAlone(t *testing.T) {
	subjects := initialCertSubjects("alice.hyperdrop.link", "203.0.113.7", true)
	if len(subjects) != 1 || subjects[0] != "203.0.113.7" {
		t.Fatalf("subjects %v, want the IP alone", subjects)
	}
	if subjects := initialCertSubjects("alice.hyperdrop.link", "", true); len(subjects) != 0 {
		t.Fatalf("subjects %v, want none", subjects)
	}
}
