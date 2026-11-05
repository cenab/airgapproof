//go:build !linux && !darwin

package engine

import "errors"

const DiskReserve uint64 = 2 << 30

func RequireSpace(string, uint64) error {
	return errors.New("bundle and VM disk-space checks require Linux or macOS")
}
