package main

import (
	"context"
	"crypto/tls"
	"strings"
	"sync/atomic"
	"time"

	"hyperdrop/server/internal/ddns"
	"hyperdrop/server/internal/domain"
	"hyperdrop/server/internal/netprobe"
)

// bootstrapCertificateSelector maps an empty SNI to the observed public IP.
// A forwarded NAS connection's local address is private, so CertMagic cannot
// infer that subject from the socket. Never change its shared config or the
// original ClientHello; ordinary domain SNI retains CertMagic's normal selection.
type bootstrapCertificateSelector struct {
	publicIP       atomic.Pointer[string]
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func (s *bootstrapCertificateSelector) observe(ip string) {
	if isPublicIPv4(ip) {
		s.publicIP.Store(&ip)
	}
}

func (s *bootstrapCertificateSelector) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		if ip := s.publicIP.Load(); ip != nil {
			named := *hello
			named.ServerName = *ip
			return s.getCertificate(&named)
		}
	}
	return s.getCertificate(hello)
}

// bootstrapIPCertificate makes pre-DNS NAS sign-in possible through the router's
// public IPv4. Observation is credential-free; only a validated public address
// is offered to ACME. ACME still proves inbound reachability on forwarded ports.
// Retry observation/registration independently of account enrollment so an
// offline first boot cannot permanently strand the setup wizard. When the
// public IP changes, the previous IP's certificate is dropped once the new
// one is managed: renewing it would fail for an address that is no longer
// this box's, again and again.
func bootstrapIPCertificate(ctx context.Context, retryInterval, refreshInterval time.Duration, observe func(context.Context) (string, error), manage func(string) error, drop func(string)) {
	managedIP := ""
	for ctx.Err() == nil {
		interval := retryInterval
		ip, err := observe(ctx)
		if err == nil && isPublicIPv4(ip) {
			if ip == managedIP || manage(ip) == nil {
				if managedIP != "" && managedIP != ip {
					drop(managedIP)
				}
				managedIP = ip
				interval = refreshInterval
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// networkObserver is the part of the names client a network probe asks.
type networkObserver interface {
	PublicIPv4(context.Context) (string, error)
	Ports(ctx context.Context, host string) (ddns.PortsObservation, error)
}

// probeNetwork classifies the NAT above this server (the router's UPnP WAN
// address against the names service's observed egress IP) and what the
// router's 443 and 80 forwards reach from outside, each port judged against
// this install's own serverID. Advisory: a failed port check, including an
// older registry's 404, leaves the last port verdict standing. The registry
// dials the address the check LEFT from, so a custom domain is judged only
// when it resolves there: one that points elsewhere (a NAS egressing through
// a VPN, a homelab published through a VPS reverse proxy) is not reached
// through these forwards, and the verdict is cleared rather than left to
// warn falsely. The free name is kept on the egress address by its own
// heartbeat, so it needs no lookup.
func probeNetwork(ctx context.Context, routerIP func(context.Context) (string, error), names networkObserver, ownID string, dom *domain.Manager) {
	router, _ := routerIP(ctx)
	public, _ := names.PublicIPv4(ctx)
	dom.SetNAT(netprobe.Verdict(router, public))
	host := dom.Current()
	obs, err := names.Ports(ctx, host)
	if err != nil {
		return
	}
	if host != "" && !strings.HasSuffix(host, "."+ddns.Zone) && !dom.PointsAt(ctx, host, obs.IP) {
		dom.ClearPorts()
		return
	}
	dom.SetPorts(domain.Ports{
		HTTPS: netprobe.PortVerdict(obs.HTTPS.Answer, obs.HTTPS.ServerID, ownID),
		HTTP:  netprobe.PortVerdict(obs.HTTP.Answer, obs.HTTP.ServerID, ownID),
	})
}
