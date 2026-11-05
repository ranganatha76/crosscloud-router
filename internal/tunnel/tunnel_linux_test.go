//go:build linux

package tunnel

import (
	"net"
	"testing"

	"github.com/ranganatha76/crosscloud-router/internal/config"
	"github.com/vishvananda/netlink"
)

func TestFindRouteConflict(t *testing.T) {
	prefix := net.IPNet{IP: net.IPv4(10, 20, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}
	routes := []netlink.Route{
		{Dst: &net.IPNet{IP: net.IPv4(10, 20, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}, LinkIndex: 2},
	}
	if err := findRouteConflict([]net.IPNet{prefix}, routes, 0); err == nil {
		t.Fatal("expected same-destination route conflict")
	}
	if err := findRouteConflict([]net.IPNet{prefix}, routes, 2); err != nil {
		t.Fatalf("owned interface route should be ignored: %v", err)
	}
}

func TestFindRouteConflictIgnoresDifferentDestination(t *testing.T) {
	prefix := net.IPNet{IP: net.IPv4(10, 20, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}
	existing := net.IPNet{IP: net.IPv4(10, 30, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}
	if err := findRouteConflict([]net.IPNet{prefix}, []netlink.Route{{Dst: &existing, LinkIndex: 2}}, 0); err != nil {
		t.Fatalf("different destination should not conflict: %v", err)
	}
}

func TestFindRouteConflictIncludesRoutesWithoutLinkIndex(t *testing.T) {
	prefix := net.IPNet{IP: net.IPv4(10, 20, 0, 0).To4(), Mask: net.CIDRMask(16, 32)}
	routes := []netlink.Route{{Dst: &prefix, LinkIndex: 0}}
	if err := findRouteConflict([]net.IPNet{prefix}, routes, 0); err == nil {
		t.Fatal("expected route without link index to conflict")
	}
}

func TestSameTopologyAllowsKeyRotationOnly(t *testing.T) {
	a := config.Config{
		Interface:  "wg0",
		MTU:        1420,
		ListenPort: 51820,
		Addresses:  []net.IPNet{{IP: net.IPv4(10, 200, 0, 1).To4(), Mask: net.CIDRMask(30, 32)}},
		Peer: config.Peer{
			Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 51820},
			AllowedIPs: []net.IPNet{{
				IP:   net.IPv4(10, 20, 0, 0).To4(),
				Mask: net.CIDRMask(16, 32),
			}},
		},
	}
	b := a
	if !sameTopology(a, b) {
		t.Fatal("equal tunnel topology should be accepted")
	}
	b.MTU++
	if sameTopology(a, b) {
		t.Fatal("MTU change must require restart")
	}
}
