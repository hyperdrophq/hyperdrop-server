package target

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// maxSourceAddrs is how far up 127.0.0.x the rig looks for source addresses.
const maxSourceAddrs = 32

// SourceAddrs answers the loopback addresses in 127.0.0.1 to 127.0.0.32 a
// listener can bind on this machine right now, in order. A stock macOS has
// only 127.0.0.1; Linux binds the whole 127/8 block.
func SourceAddrs() []net.IP {
	var out []net.IP
	for i := 1; i <= maxSourceAddrs; i++ {
		ip := net.IPv4(127, 0, 0, byte(i))
		l, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			continue
		}
		l.Close()
		out = append(out, ip)
	}
	return out
}

// AliasHint is what a person runs to make n loopback source addresses
// available, one command per line. The rig never runs it.
func AliasHint(n int) string {
	n = max(1, min(n, maxSourceAddrs))
	if runtime.GOOS != "darwin" {
		return fmt.Sprintf("no setup needed: Linux binds all of 127.0.0.0/8 (%d addresses wanted)", n)
	}
	var b strings.Builder
	for i := 2; i <= n; i++ {
		fmt.Fprintf(&b, "sudo ifconfig lo0 alias 127.0.0.%d up\n", i)
	}
	if b.Len() == 0 {
		return "no setup needed: 127.0.0.1 is the only address wanted"
	}
	return strings.TrimRight(b.String(), "\n")
}
