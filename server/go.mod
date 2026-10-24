module hyperdrop/server

go 1.27.3

require (
	github.com/caddyserver/certmagic v0.25.4
	github.com/huin/goupnp v1.3.0
	github.com/klauspost/compress v1.19.0
	github.com/mholt/acmez/v3 v3.1.6
	github.com/pires/go-proxyproto v0.15.0
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
	golang.org/x/text v0.42.0
	hyperdrop/core v0.0.0
	modernc.org/sqlite v1.55.0
)

require (
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The server imports the client core's pure decision packages
// (TestServerImportsOnlyPureCore lists them) from the checkout.
replace hyperdrop/core => ../core
