//go:build linux || darwin

package engine

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const DiskReserve uint64 = 2 << 30

func RequireSpace(path string, bytes uint64) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return fmt.Errorf("check disk space: %w", err)
	}
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	if bytes > available {
		return fmt.Errorf("insufficient disk space: need %.1f GiB, available %.1f GiB at %s", float64(bytes)/(1<<30), float64(available)/(1<<30), path)
	}
	return nil
}
