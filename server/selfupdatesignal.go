//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchSelfUpdateSwitch calls reread on every SIGUSR1 until ctx ends: the
// operator's auto-update command turned the switch in the database, and the
// running server checks at once when it is now on.
func watchSelfUpdateSwitch(ctx context.Context, reread func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				reread()
			}
		}
	}()
}
