//go:build !linux

package sharefs

import "os"

// cloneFileOS has no clone to ask outside Linux: the server ships for Linux,
// and a development build elsewhere copies.
func cloneFileOS(dst, src *os.File) error { return errNoClone }
