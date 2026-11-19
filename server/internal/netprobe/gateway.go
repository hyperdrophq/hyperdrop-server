package netprobe

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxBody is the most a gateway's answer may carry.
const maxBody = 64 << 10

const rtfGateway = 0x2

var errBodyTooLarge = errors.New("gateway answer exceeds 64 KiB")

// notGatewayError reports a dial to an address other than the gateway.
type notGatewayError struct{ addr string }

func (e notGatewayError) Error() string {
	return "refusing to dial " + e.addr + ": not the default gateway"
}

// DefaultGateway returns the IPv4 default gateway from /proc/net/route.
func DefaultGateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	return parseRoute(f)
}

// parseRoute reads /proc/net/route and returns the gateway of the default
// route: Destination 00000000 with the RTF_GATEWAY flag. Addresses are
// little-endian hex.
func parseRoute(r io.Reader) (netip.Addr, error) {
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		gw := netip.AddrFrom4(b)
		if gw.IsUnspecified() {
			continue
		}
		return gw, nil
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, err
	}
	return netip.Addr{}, errNoGateway
}

// gatewayClient returns an HTTP client that dials only gw, follows no
// redirect and reads at most maxBody bytes of any response.
func gatewayClient(gw netip.Addr) *http.Client {
	var d net.Dialer
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &limitTransport{base: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if a, err := netip.ParseAddr(host); err != nil || a.Unmap() != gw {
					return nil, notGatewayError{addr}
				}
				return d.DialContext(ctx, network, addr)
			},
			DisableKeepAlives: true,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type limitTransport struct{ base http.RoundTripper }

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{rc: resp.Body, left: maxBody}
	return resp, nil
}

// limitedBody fails once more than left bytes would be read.
type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n - 1, errBodyTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// checkLocation reports whether a device description's LOCATION names gw.
func checkLocation(host string, gw netip.Addr) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap() == gw
}
