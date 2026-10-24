package main

import (
	"net"
	"net/http"
	"time"
)

// waitServing reports whether any of urls answers 200 before the deadline,
// probing each every interval. It is the boot self-check's engine: run
// against the server's own plain-HTTP health route so a process that starts
// but cannot serve exits nonzero instead of sitting active-but-broken, which
// is the state the updater's rollback cannot see.
func waitServing(deadline, interval time.Duration, urls ...string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	end := time.Now().Add(deadline)
	for {
		for _, url := range urls {
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return true
				}
			}
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(interval)
	}
}

// selfCheckURLs are the health URLs the boot self-check dials for the
// plain-HTTP listen address addr: the listener's own host, since a server
// bound to one address refuses a dial to any other, or loopback when addr
// names none or the unspecified address. A wildcard listener accepts
// whichever loopback the box has: [::] is dual-stack unless the kernel binds
// IPv6 sockets to IPv6 alone, and a container with IPv6 disabled has no ::1,
// so it is dialled at 127.0.0.1 and then at ::1, and passes on either. ok is
// false for an address without a port.
func selfCheckURLs(addr string) (urls []string, ok bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return nil, false
	}
	hosts := []string{host}
	switch ip := net.ParseIP(host); {
	case host == "" || (ip != nil && ip.To4() != nil && ip.IsUnspecified()):
		hosts = []string{"127.0.0.1"}
	case ip != nil && ip.IsUnspecified():
		hosts = []string{"127.0.0.1", "::1"}
	}
	for _, h := range hosts {
		urls = append(urls, "http://"+net.JoinHostPort(h, port)+"/api/health")
	}
	return urls, true
}
