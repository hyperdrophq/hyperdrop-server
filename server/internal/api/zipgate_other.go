//go:build !unix

package api

// filesToSpare has no count to read on this system, and answers yes.
func filesToSpare() bool { return true }

// machineMemory has nothing to read on this system.
func machineMemory() (total, available int64) { return 0, 0 }
