package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoadValidConfig(t *testing.T) {
	raw := validFile(t)
	cfg := loadRaw(t, raw)
	if cfg.Interface != "wg-crosscloud" {
		t.Fatalf("unexpected interface %q", cfg.Interface)
	}
	if got, want := len(cfg.Peer.AllowedIPs), 2; got != want {
		t.Fatalf("got %d allowed IP prefixes, want %d", got, want)
	}
	if got, want := cfg.Peer.PersistentKeepalive.Seconds(), float64(25); got != want {
		t.Fatalf("got keepalive %v, want %v", got, want)
	}
	if got, want := cfg.Peer.AllowedIPs[1].String(), "10.20.0.0/16"; got != want {
		t.Fatalf("got normalized allowed prefix %q, want %q", got, want)
	}
}

func TestRejectsDefaultRoute(t *testing.T) {
	raw := validFile(t)
	raw.Peer.AllowedIPs = []string{"0.0.0.0/0"}
	if _, err := parse(raw); err == nil {
		t.Fatal("expected default route to be rejected")
	}
}

func TestRejectsPeerPrefixContainingLocalAddress(t *testing.T) {
	raw := validFile(t)
	raw.Peer.AllowedIPs = []string{"10.200.0.0/29"}
	if _, err := parse(raw); err == nil {
		t.Fatal("expected prefix containing local tunnel address to be rejected")
	}
}

func TestRejectsEndpointInsidePeerRoute(t *testing.T) {
	raw := validFile(t)
	raw.Peer.Endpoint = "10.20.0.5:51820"
	if _, err := parse(raw); err == nil {
		t.Fatal("expected endpoint route recursion to be rejected")
	}
}

func TestRejectsDuplicateAllowedPrefix(t *testing.T) {
	raw := validFile(t)
	raw.Peer.AllowedIPs = []string{"10.20.0.0/16", "10.20.0.0/16"}
	if _, err := parse(raw); err == nil {
		t.Fatal("expected duplicate prefix to be rejected")
	}
}

func TestRejectsInsecurePrivateKeyPermissions(t *testing.T) {
	raw := validFile(t)
	if err := os.Chmod(raw.PrivateKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(raw); err == nil {
		t.Fatal("expected private key with broad permissions to be rejected")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	raw := validFile(t)
	data, err := json.Marshal(map[string]any{
		"interface":        raw.Interface,
		"addresses":        raw.Addresses,
		"mtu":              raw.MTU,
		"listen_port":      raw.ListenPort,
		"private_key_file": raw.PrivateKeyFile,
		"peer":             raw.Peer,
		"unexpected":       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown config field to be rejected")
	}
}

func TestLoadRejectsDuplicateJSONKeys(t *testing.T) {
	raw := validFile(t)
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"mtu":1500}`)...)
	path := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate key to be rejected")
	}
}

func TestRejectsMTUOutsideSupportedRange(t *testing.T) {
	raw := validFile(t)
	raw.MTU = 1279
	if _, err := parse(raw); err == nil {
		t.Fatal("expected out-of-range MTU to be rejected")
	}
}

func validFile(t *testing.T) File {
	t.Helper()
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(keyPath, []byte(privateKey.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return File{
		Interface:      "wg-crosscloud",
		Addresses:      []string{"10.200.0.1/30"},
		MTU:            1420,
		ListenPort:     51820,
		PrivateKeyFile: keyPath,
		Peer: PeerFile{
			PublicKey:                  peerKey.PublicKey().String(),
			Endpoint:                   "198.51.100.20:51820",
			AllowedIPs:                 []string{"10.200.0.2/32", "10.20.0.0/16"},
			PersistentKeepaliveSeconds: 25,
		},
	}
}

func loadRaw(t *testing.T, raw File) Config {
	t.Helper()
	cfg, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
