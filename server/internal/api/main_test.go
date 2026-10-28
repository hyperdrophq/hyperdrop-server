package api

import (
	"os"
	"testing"
)

// TestMain runs the package with the fresh-device rule off, so the tokens a
// test mints a moment apart can sign each other out; a test of the rule
// itself turns it on with withFreshDeviceRule.
func TestMain(m *testing.M) {
	freshDeviceAge = 0
	os.Exit(m.Run())
}
