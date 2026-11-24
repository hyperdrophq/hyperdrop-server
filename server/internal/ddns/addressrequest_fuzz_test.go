package ddns

import (
	"strings"
	"testing"

	"hyperdrop/server/internal/domain"
)

// An address request is a file's text. One that parses names a free name the
// names service issues, or a lowercase domain outside the free-name zone.
func FuzzParseAddressRequest(f *testing.F) {
	for _, s := range []string{"free myname\n", "domain Example.COM.\n", "domain x." + Zone, "free a b", "domain example.com\nfree x", " free  x ", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		req, ok := ParseAddressRequest(s)
		if !ok {
			if req != (AddressRequest{}) {
				t.Fatalf("a refused request answered %+v", req)
			}
			return
		}
		if req.Free {
			if !ValidName(req.Name) {
				t.Fatalf("ParseAddressRequest(%q) = free %q", s, req.Name)
			}
			return
		}
		if !domain.Valid(req.Name) || req.Name != strings.ToLower(req.Name) || strings.HasSuffix(req.Name, ".") ||
			req.Name == Zone || InFreeZone(req.Name) {
			t.Fatalf("ParseAddressRequest(%q) = domain %q", s, req.Name)
		}
	})
}
