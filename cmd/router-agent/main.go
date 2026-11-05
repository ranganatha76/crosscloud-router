package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ranganatha76/crosscloud-router/internal/config"
	"github.com/ranganatha76/crosscloud-router/internal/tunnel"
)

func main() {
	configPath := flag.String("config", "/etc/crosscloud-router/node.json", "path to the node JSON configuration")
	checkOnly := flag.Bool("check", false, "validate configuration and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("router-agent: %v", err)
		os.Exit(1)
	}

	if *checkOnly {
		log.Printf("configuration is valid for interface %q", cfg.Interface)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	if err := tunnel.Run(ctx, cfg, *configPath, reload); err != nil {
		log.Printf("router-agent: %v", err)
		os.Exit(1)
	}
}
