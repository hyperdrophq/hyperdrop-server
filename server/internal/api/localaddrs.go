package api

// The LAN-shortcut discovery source: the server names its own private
// addresses so the client never asks the user for an IP. Authenticated,
// deliberately not on the open health route: LAN topology is not for
// unauthenticated callers. The client authenticates every candidate anyway
// (a TLS handshake for the PUBLIC name), so this list is a hint, not a
// trusted input.

import (
	"net"
	"net/http"
)

// serverInterfaceAddrs is replaced in tests.
var serverInterfaceAddrs = func() []net.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Addr
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		a, err := i.Addrs()
		if err != nil {
			continue
		}
		out = append(out, a...)
	}
	return out
}

// localAddressCandidates: private IPv4 only, joined with the HTTPS listen
// port. An empty port (plain-HTTP dev mode) reports nothing: the client
// refuses a plain-HTTP local path anyway.
func localAddressCandidates(addrs []net.Addr, port string) []string {
	if port == "" {
		return nil
	}
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP.To4()
		if ip == nil || !ip.IsPrivate() {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out
}

func (h *handler) localAddresses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"addresses": localAddressCandidates(serverInterfaceAddrs(), h.dep.LocalPort),
	})
}
