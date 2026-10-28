package sharefs

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
	ErrBadPath    = fmt.Errorf("%w: invalid path", ErrBadRequest)
	ErrDiskFull   = errors.New("disk full")
	ErrNoSpace    = errors.New("not enough space on the server")
	ErrNoThumb    = errors.New("no thumbnail")
	ErrNoPoster   = errors.New("no poster")
)
