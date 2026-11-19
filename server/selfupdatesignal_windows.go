package main

import "context"

// watchSelfUpdateSwitch does nothing on Windows, where the server runs only
// as a development build that never updates itself.
func watchSelfUpdateSwitch(context.Context, func()) {}
