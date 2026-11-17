//go:build linux

package report

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func cpuAndMemory() (string, int64) {
	var cpu string
	var mem int64
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
				cpu = strings.TrimSpace(v)
				break
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(l, "MemTotal:"); ok {
				mem = atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB")) * 1024
				break
			}
		}
	}
	return cpu, mem
}

var fsMagic = map[int64]string{
	0xEF53: "ext4", 0x58465342: "xfs", 0x9123683E: "btrfs", 0x01021994: "tmpfs",
	0x2FC12FC1: "zfs", 0x794C7630: "overlayfs", 0xF2F52010: "f2fs", 0x6969: "nfs",
}

func fileSystemOf(dir string) string {
	var st syscall.Statfs_t
	if dir == "" || syscall.Statfs(dir, &st) != nil {
		return ""
	}
	if n, ok := fsMagic[int64(st.Type)]; ok {
		return n
	}
	return fmt.Sprintf("0x%x", int64(st.Type))
}
