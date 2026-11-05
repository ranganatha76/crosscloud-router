//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ranganatha76/crosscloud-router/internal/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	managedAlias         = "crosscloud-router-managed"
	managedRouteProtocol = 253
	healthInterval       = 30 * time.Second
)

func Run(ctx context.Context, cfg config.Config, configPath string, reload <-chan os.Signal) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	lock, err := acquireLock(cfg.Interface)
	if err != nil {
		return err
	}
	defer lock.Close()

	var stale netlink.Link
	if existing, err := netlink.LinkByName(cfg.Interface); err == nil {
		if existing.Type() != "wireguard" || existing.Attrs().Alias != managedAlias {
			return fmt.Errorf("interface %q already exists and is not owned by this agent", cfg.Interface)
		}
		stale = existing
	} else {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("inspect interface %q: %w", cfg.Interface, err)
		}
	}

	var ignoredLink int
	if stale != nil {
		ignoredLink = stale.Attrs().Index
	}
	if err := checkRouteConflicts(cfg.Peer.AllowedIPs, ignoredLink); err != nil {
		return err
	}
	if stale != nil {
		staleRoutes, err := netlink.RouteList(stale, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("inspect routes on stale managed interface: %w", err)
		}
		for _, route := range staleRoutes {
			if route.Protocol == managedRouteProtocol {
				if err := netlink.RouteDel(&route); err != nil {
					return fmt.Errorf("remove stale managed route %s: %w", route.Dst, err)
				}
			}
		}
		if err := netlink.LinkDel(stale); err != nil {
			return fmt.Errorf("remove stale managed interface %q: %w", cfg.Interface, err)
		}
	}

	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: cfg.Interface, Alias: managedAlias, MTU: cfg.MTU}}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create WireGuard interface %q: %w", cfg.Interface, err)
	}
	owned, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return errors.Join(fmt.Errorf("find created interface: %w", err), netlink.LinkDel(link))
	}

	routes := make([]netlink.Route, 0, len(cfg.Peer.AllowedIPs))
	cleanup := func() error {
		var cleanupErr error
		for i := len(routes) - 1; i >= 0; i-- {
			if err := netlink.RouteDel(&routes[i]); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove route %s: %w", routes[i].Dst, err))
			}
		}
		if err := netlink.LinkDel(owned); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove interface %q: %w", cfg.Interface, err))
		}
		return cleanupErr
	}
	fail := func(err error) error {
		return errors.Join(err, cleanup())
	}

	if err := netlink.LinkSetMTU(owned, cfg.MTU); err != nil {
		return fail(fmt.Errorf("set tunnel MTU: %w", err))
	}
	for _, address := range cfg.Addresses {
		if err := netlink.AddrAdd(owned, &netlink.Addr{IPNet: &address}); err != nil {
			return fail(fmt.Errorf("add tunnel address %s: %w", address.String(), err))
		}
	}
	if err := netlink.LinkSetUp(owned); err != nil {
		return fail(fmt.Errorf("bring up tunnel interface: %w", err))
	}

	client, err := wgctrl.New()
	if err != nil {
		return fail(fmt.Errorf("connect to WireGuard control interface: %w", err))
	}
	defer client.Close()
	if err := configureDevice(client, cfg); err != nil {
		return fail(fmt.Errorf("configure WireGuard peer: %w", err))
	}

	for _, allowed := range cfg.Peer.AllowedIPs {
		destination := allowed
		destination.IP = destination.IP.Mask(destination.Mask)
		route := netlink.Route{
			LinkIndex: owned.Attrs().Index,
			Dst:       &destination,
			Protocol:  managedRouteProtocol,
		}
		if err := netlink.RouteAdd(&route); err != nil {
			return fail(fmt.Errorf("add route %s through %s: %w", destination.String(), cfg.Interface, err))
		}
		routes = append(routes, route)
	}

	log.Printf("WireGuard tunnel %s is up", cfg.Interface)
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping WireGuard tunnel %s", cfg.Interface)
			return cleanup()
		case _, ok := <-reload:
			if !ok {
				reload = nil
				continue
			}
			next, err := config.Load(configPath)
			if err != nil {
				log.Printf("configuration reload rejected: %v", err)
				continue
			}
			if !sameTopology(cfg, next) {
				log.Printf("configuration reload rejected: topology changes require a service restart")
				continue
			}
			if err := configureKeys(client, next); err != nil {
				log.Printf("configuration key rotation failed: %v", err)
				continue
			}
			cfg = next
			log.Printf("WireGuard keys reloaded for %s", cfg.Interface)
		case <-ticker.C:
			if err := checkHealth(client, cfg, owned); err != nil {
				log.Printf("tunnel health check failed; will retry without tearing down the tunnel: %v", err)
			}
		}
	}
}

func configureDevice(client *wgctrl.Client, cfg config.Config) error {
	keepalive := cfg.Peer.PersistentKeepalive
	peer := wgtypes.PeerConfig{
		PublicKey:                   cfg.Peer.PublicKey,
		PresharedKey:                cfg.Peer.PresharedKey,
		Endpoint:                    cfg.Peer.Endpoint,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  cfg.Peer.AllowedIPs,
	}
	return client.ConfigureDevice(cfg.Interface, wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ListenPort:   &cfg.ListenPort,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peer},
	})
}

func configureKeys(client *wgctrl.Client, cfg config.Config) error {
	preshared := wgtypes.Key{}
	if cfg.Peer.PresharedKey != nil {
		preshared = *cfg.Peer.PresharedKey
	}
	return client.ConfigureDevice(cfg.Interface, wgtypes.Config{
		PrivateKey: &cfg.PrivateKey,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:    cfg.Peer.PublicKey,
			PresharedKey: &preshared,
		}},
	})
}

func sameTopology(a, b config.Config) bool {
	if a.Interface != b.Interface || a.MTU != b.MTU || a.ListenPort != b.ListenPort ||
		a.Peer.PublicKey != b.Peer.PublicKey ||
		a.Peer.Endpoint.String() != b.Peer.Endpoint.String() ||
		a.Peer.PersistentKeepalive != b.Peer.PersistentKeepalive ||
		len(a.Addresses) != len(b.Addresses) ||
		len(a.Peer.AllowedIPs) != len(b.Peer.AllowedIPs) {
		return false
	}
	for i := range a.Addresses {
		if a.Addresses[i].String() != b.Addresses[i].String() {
			return false
		}
	}
	for i := range a.Peer.AllowedIPs {
		if a.Peer.AllowedIPs[i].String() != b.Peer.AllowedIPs[i].String() {
			return false
		}
	}
	return true
}

func checkRouteConflicts(prefixes []net.IPNet, ignoreLinkIndex int) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list existing routes: %w", err)
	}
	return findRouteConflict(prefixes, routes, ignoreLinkIndex)
}

func findRouteConflict(prefixes []net.IPNet, routes []netlink.Route, ignoreLinkIndex int) error {
	for _, prefix := range prefixes {
		candidate := prefix
		candidate.IP = candidate.IP.Mask(candidate.Mask)
		for _, route := range routes {
			ownedRoute := ignoreLinkIndex != 0 && route.LinkIndex == ignoreLinkIndex
			if !ownedRoute && route.Dst != nil && route.Dst.String() == candidate.String() {
				return fmt.Errorf("route %s already exists (link index %d, protocol %d); resolve the conflict before starting", candidate.String(), route.LinkIndex, route.Protocol)
			}
		}
	}
	return nil
}

func checkHealth(client *wgctrl.Client, cfg config.Config, owned netlink.Link) error {
	current, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("find tunnel interface: %w", err)
	}
	if current.Type() != "wireguard" || current.Attrs().Alias != managedAlias || current.Attrs().Index != owned.Attrs().Index {
		return fmt.Errorf("tunnel interface ownership or type changed")
	}
	if current.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(current); err != nil {
			return fmt.Errorf("restore tunnel interface state: %w", err)
		}
		log.Printf("recovered down tunnel interface %s", cfg.Interface)
	}

	routes, err := netlink.RouteList(owned, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list tunnel routes: %w", err)
	}
	for _, prefix := range cfg.Peer.AllowedIPs {
		expected := prefix
		expected.IP = expected.IP.Mask(expected.Mask)
		if hasManagedRoute(routes, expected) {
			continue
		}
		if err := checkRouteConflicts([]net.IPNet{expected}, owned.Attrs().Index); err != nil {
			return fmt.Errorf("required route %s is missing and cannot be safely restored: %w", expected.String(), err)
		}
		route := netlink.Route{
			LinkIndex: owned.Attrs().Index,
			Dst:       &expected,
			Protocol:  managedRouteProtocol,
		}
		if err := netlink.RouteAdd(&route); err != nil {
			return fmt.Errorf("restore route %s: %w", expected.String(), err)
		}
		log.Printf("recovered missing route %s", expected.String())
	}

	device, err := client.Device(cfg.Interface)
	if err != nil {
		return fmt.Errorf("read WireGuard device status: %w", err)
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == cfg.Peer.PublicKey {
			handshake := "never"
			if !peer.LastHandshakeTime.IsZero() {
				handshake = time.Since(peer.LastHandshakeTime).Round(time.Second).String() + " ago"
			}
			log.Printf("health interface=%s peer=%s handshake=%s rx_bytes=%d tx_bytes=%d",
				cfg.Interface, peer.PublicKey.String(), handshake, peer.ReceiveBytes, peer.TransmitBytes)
			return nil
		}
	}
	if err := configureDevice(client, cfg); err != nil {
		return fmt.Errorf("configured WireGuard peer is missing and could not be restored: %w", err)
	}
	log.Printf("restored missing WireGuard peer on %s", cfg.Interface)
	return nil
}

func hasManagedRoute(routes []netlink.Route, expected net.IPNet) bool {
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == expected.String() && route.Protocol == managedRouteProtocol {
			return true
		}
	}
	return false
}

func acquireLock(interfaceName string) (*os.File, error) {
	dir := "/run/crosscloud-router"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create runtime directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("runtime directory must be a non-writable-by-others directory")
	}
	dirOwner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || dirOwner.Uid != 0 {
		return nil, fmt.Errorf("runtime directory must be owned by root")
	}

	lockPath := filepath.Join(dir, interfaceName+".lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open agent lock: %w", err)
	}
	lockInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("inspect agent lock: %w", err)
	}
	lockOwner, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !lockInfo.Mode().IsRegular() || !ok || lockOwner.Uid != 0 || lockInfo.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, fmt.Errorf("agent lock must be a root-owned private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another agent instance is managing interface %q: %w", interfaceName, err)
	}
	return file, nil
}
