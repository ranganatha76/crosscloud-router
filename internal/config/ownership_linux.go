//go:build linux

package config

import (
	"fmt"
	"os"
	"syscall"
)

func requireRootOwner(info os.FileInfo) error {
	if os.Geteuid() != 0 {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("file must be owned by root")
	}
	return nil
}
