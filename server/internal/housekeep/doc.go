// Package housekeep is the server's maintenance pass: every five minutes,
// expired shares, due scheduled changes, stalled uploads, empty shares,
// old journal rows, old device links, the planner's statistics and the
// daily backup. Each step is a query first and disk second, and none walks
// shares/: a volume with nothing due costs no syscalls under it.
package housekeep
