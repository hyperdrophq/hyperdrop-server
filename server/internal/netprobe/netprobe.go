// Package netprobe answers one question for a server behind NAT: can a
// router forward ever deliver inbound traffic here? It compares the
// router's WAN address (asked over UPnP) with the address the HyperDrop names
// service sees and classifies the difference. Everything here
// is advisory: an unreachable router or names service yields "unknown", which
// callers must treat as no information, never as a fault.
package netprobe

import (
	"context"
	"errors"
	"net/netip"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Verdict classifies the NAT above this server. "direct": the router holds
// the public address, forwarding works. "cgnat": the router's WAN address is
// carrier-grade, forwarding cannot work. "layered": a second NAT sits above
// the router. "unknown": a probe failed, nothing is claimed.
func Verdict(routerWAN, publicIP string) string {
	r, err := netip.ParseAddr(routerWAN)
	if err != nil {
		return "unknown"
	}
	if cgnat.Contains(r) {
		return "cgnat"
	}
	if publicIP == "" {
		return "unknown"
	}
	if r.IsPrivate() {
		return "layered"
	}
	if routerWAN == publicIP {
		return "direct"
	}
	return "layered"
}

var errNoGateway = errors.New("no UPnP gateway answered")

// RouterExternalIP asks the LAN's UPnP gateway for its WAN address, trying
// the three service types consumer routers actually expose.
func RouterExternalIP(ctx context.Context) (string, error) {
	if c, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx); err == nil && len(c) > 0 {
		if ip, err := c[0].GetExternalIPAddress(); err == nil && ip != "" {
			return ip, nil
		}
	}
	if c, _, err := internetgateway1.NewWANPPPConnection1ClientsCtx(ctx); err == nil && len(c) > 0 {
		if ip, err := c[0].GetExternalIPAddress(); err == nil && ip != "" {
			return ip, nil
		}
	}
	c, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err != nil {
		return "", err
	}
	if len(c) == 0 {
		return "", errNoGateway
	}
	return c[0].GetExternalIPAddress()
}

// PortVerdict classifies one public port from the names service's dial back:
// "ok" (this very install answered), "taken" (something else answered,
// including another HyperDrop install), "closed" (nothing took the
// connection), "unknown" (no claim). Only taken and closed are worth words.
func PortVerdict(answer, serverID, ownID string) string {
	switch answer {
	case "hyperdrop":
		if serverID == ownID {
			return "ok"
		}
		return "taken"
	case "other":
		return "taken"
	case "none":
		return "closed"
	}
	return "unknown"
}
