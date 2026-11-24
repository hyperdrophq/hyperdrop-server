//go:build !darwin && !linux

package report

func cpuAndMemory() (string, int64) { return "", 0 }

func fileSystemOf(string) string { return "" }
