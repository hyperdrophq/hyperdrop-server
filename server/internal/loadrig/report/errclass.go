package report

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
func isReset(err error) bool   { return errors.Is(err, syscall.ECONNRESET) }
