package ddns

import (
	"strings"

	"hyperdrop/server/internal/domain"
)

// AddressRequest is a parsed address request: a free name (the bare name) or
// an own domain (lowercase, without a trailing dot).
type AddressRequest struct {
	Free bool
	Name string
}

// ParseAddressRequest reads the address request's grammar, which the server
// carries out and the DSM page shows: exactly one line, "free <name>" with a
// name the names service issues, or "domain <fqdn>" with a domain outside the
// free-name zone. ok is false for anything else.
func ParseAddressRequest(s string) (req AddressRequest, ok bool) {
	line, rest, _ := strings.Cut(s, "\n")
	if strings.TrimSpace(rest) != "" {
		return AddressRequest{}, false
	}
	kind, value, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok {
		return AddressRequest{}, false
	}
	switch kind {
	case "free":
		if ValidName(value) {
			return AddressRequest{Free: true, Name: value}, true
		}
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(value), ".")
		if domain.Valid(d) && d != Zone && !InFreeZone(d) {
			return AddressRequest{Name: d}, true
		}
	}
	return AddressRequest{}, false
}
