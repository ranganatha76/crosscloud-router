//go:build !linux

package config

import "os"

func requireRootOwner(os.FileInfo) error {
	return nil
}
