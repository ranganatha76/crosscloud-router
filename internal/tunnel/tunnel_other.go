//go:build !linux

package tunnel

import (
	"context"
	"fmt"
	"os"

	"github.com/ranganatha76/crosscloud-router/internal/config"
)

func Run(context.Context, config.Config, string, <-chan os.Signal) error {
	return fmt.Errorf("running a WireGuard tunnel is supported only on Linux")
}
