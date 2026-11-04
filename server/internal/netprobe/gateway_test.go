package netprobe

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const routeFixture = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
	"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

func TestParseRouteFindsTheDefaultGateway(t *testing.T) {
	gw, err := parseRoute(strings.NewReader(routeFixture))
	if err != nil {
		t.Fatal(err)
	}
	if gw != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("gateway = %v", gw)
	}
}

func TestParseRouteWithoutADefaultErrors(t *testing.T) {
	onlyLAN := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if _, err := parseRoute(strings.NewReader(onlyLAN)); err == nil {
		t.Fatal("want an error")
	}
}

func listenerAddr(t *testing.T, srv *httptest.Server) netip.Addr {
	t.Helper()
	host, _, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return netip.MustParseAddr(host)
}

func TestTheGatewayClientRefusesAnotherHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := gatewayClient(netip.MustParseAddr("192.0.2.1"))
	if resp, err := c.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("dialled a host that is not the gateway")
	}
	c = gatewayClient(listenerAddr(t, srv))
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestTheGatewayClientFollowsNoRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect was followed")
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	resp, err := gatewayClient(listenerAddr(t, srv)).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestTheGatewayClientStopsAt64KiB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", maxBody+1)))
	}))
	defer srv.Close()
	resp, err := gatewayClient(listenerAddr(t, srv)).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil {
		t.Fatalf("read %d bytes without an error", n)
	}
	if n > maxBody {
		t.Fatalf("read %d bytes", n)
	}
}
