// Package bytefmt renders a byte count the way a person reads it.
//
// It is the one implementation behind the store's quota and out-of-space
// refusals, the health verdict's free-disk and memory sentences, and the
// public file listing, so one number reads the same wherever a user meets it.
package bytefmt

import "fmt"

// Decimal renders n in powers of 1000: 91_700_000_000 is "91.7 GB".
//
// This is what a person is TOLD a size is. macOS's ByteCountFormatter with
// countStyle .file is decimal, so it is what the app shows, and a binary
// divisor labelled "GB" would make one file read as 85.4 GB here and 91.7 GB
// in the app. Anything the user reads beside the app's own figure uses this.
func Decimal(n int64) string { return format(n, 1000, "KMGTPE") }

// Binary renders n in powers of 1024: 91_700_000_000 is "85.4 GB".
//
// For sizes stated next to something the user typed in binary units, since
// `--quota 10G` is 10*1024^3 and echoing it as "10.7 GB" reads as a different
// number from the one they set.
func Binary(n int64) string { return format(n, 1024, "KMGTPE") }

// format is the shared ladder. Below one unit the count is exact, because
// "612 B" is a fact and "0.6 KB" is a rounding of one.
func format(n, unit int64, units string) string {
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := unit, 0
	for v := n / unit; v >= unit && exp < len(units)-1; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), units[exp])
}
