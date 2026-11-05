package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const maxConfigSize = 1 << 20

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

type File struct {
	Interface      string   `json:"interface"`
	Addresses      []string `json:"addresses"`
	MTU            int      `json:"mtu"`
	ListenPort     int      `json:"listen_port"`
	PrivateKeyFile string   `json:"private_key_file"`
	Peer           PeerFile `json:"peer"`
}

type PeerFile struct {
	PublicKey                  string   `json:"public_key"`
	PresharedKeyFile           string   `json:"preshared_key_file,omitempty"`
	Endpoint                   string   `json:"endpoint"`
	AllowedIPs                 []string `json:"allowed_ips"`
	PersistentKeepaliveSeconds int      `json:"persistent_keepalive_seconds"`
}

type Config struct {
	Interface  string
	Addresses  []net.IPNet
	MTU        int
	ListenPort int
	PrivateKey wgtypes.Key
	Peer       Peer
}

type Peer struct {
	PublicKey           wgtypes.Key
	PresharedKey        *wgtypes.Key
	Endpoint            *net.UDPAddr
	AllowedIPs          []net.IPNet
	PersistentKeepalive time.Duration
}

func Load(path string) (Config, error) {
	data, info, err := readRegularFile(path, maxConfigSize)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	if info.Mode().Perm()&0022 != 0 {
		return Config{}, fmt.Errorf("config file must not be group- or world-writable")
	}

	if err := requireRootOwner(info); err != nil {
		return Config{}, fmt.Errorf("config file ownership: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw File
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config: expected exactly one JSON object")
	}

	return parse(raw)
}

func parse(raw File) (Config, error) {
	if !interfaceNamePattern.MatchString(raw.Interface) || raw.Interface == "." || raw.Interface == ".." {
		return Config{}, fmt.Errorf("interface must be a valid Linux interface name (1-15 safe characters)")
	}
	if raw.ListenPort < 1 || raw.ListenPort > 65535 {
		return Config{}, fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if len(raw.Addresses) == 0 {
		return Config{}, fmt.Errorf("at least one interface address is required")
	}
	if raw.MTU < 1280 || raw.MTU > 9000 {
		return Config{}, fmt.Errorf("mtu must be between 1280 and 9000")
	}
	if strings.TrimSpace(raw.PrivateKeyFile) == "" {
		return Config{}, fmt.Errorf("private_key_file is required")
	}
	if !filepath.IsAbs(raw.PrivateKeyFile) {
		return Config{}, fmt.Errorf("private_key_file must be an absolute path")
	}
	if raw.Peer.PresharedKeyFile != "" && !filepath.IsAbs(raw.Peer.PresharedKeyFile) {
		return Config{}, fmt.Errorf("peer.preshared_key_file must be an absolute path")
	}
	if len(raw.Peer.AllowedIPs) == 0 {
		return Config{}, fmt.Errorf("peer.allowed_ips must contain at least one prefix")
	}
	if raw.Peer.PersistentKeepaliveSeconds < 0 || raw.Peer.PersistentKeepaliveSeconds > 300 {
		return Config{}, fmt.Errorf("peer.persistent_keepalive_seconds must be between 0 and 300")
	}

	privateKeyText, err := readSecret(raw.PrivateKeyFile)
	if err != nil {
		return Config{}, fmt.Errorf("read private key: %w", err)
	}
	privateKey, err := wgtypes.ParseKey(strings.TrimSpace(privateKeyText))
	if err != nil {
		return Config{}, fmt.Errorf("parse private key: %w", err)
	}
	if privateKey == (wgtypes.Key{}) {
		return Config{}, fmt.Errorf("private key must not be all zeroes")
	}
	publicKey, err := wgtypes.ParseKey(raw.Peer.PublicKey)
	if err != nil {
		return Config{}, fmt.Errorf("parse peer public_key: %w", err)
	}
	if publicKey == (wgtypes.Key{}) {
		return Config{}, fmt.Errorf("peer public_key must not be all zeroes")
	}
	if privateKey.PublicKey() == publicKey {
		return Config{}, fmt.Errorf("peer public_key must not be this node's public key")
	}

	endpoint, err := parseEndpoint(raw.Peer.Endpoint)
	if err != nil {
		return Config{}, err
	}

	addresses, err := parsePrefixes(raw.Addresses, "addresses", false)
	if err != nil {
		return Config{}, err
	}
	allowedIPs, err := parsePrefixes(raw.Peer.AllowedIPs, "peer.allowed_ips", true)
	if err != nil {
		return Config{}, err
	}
	for _, local := range addresses {
		for _, remote := range allowedIPs {
			if remote.Contains(local.IP) {
				return Config{}, fmt.Errorf("peer.allowed_ips prefix %s contains local tunnel address %s", remote.String(), local.IP)
			}
		}
	}
	for _, remote := range allowedIPs {
		if remote.Contains(endpoint.IP) {
			return Config{}, fmt.Errorf("peer endpoint %s is inside allowed prefix %s; this can route the tunnel endpoint through itself", endpoint.IP, remote.String())
		}
	}

	var presharedKey *wgtypes.Key
	if raw.Peer.PresharedKeyFile != "" {
		text, err := readSecret(raw.Peer.PresharedKeyFile)
		if err != nil {
			return Config{}, fmt.Errorf("read preshared key: %w", err)
		}
		key, err := wgtypes.ParseKey(strings.TrimSpace(text))
		if err != nil {
			return Config{}, fmt.Errorf("parse preshared key: %w", err)
		}
		presharedKey = &key
	}

	return Config{
		Interface:  raw.Interface,
		Addresses:  addresses,
		MTU:        raw.MTU,
		ListenPort: raw.ListenPort,
		PrivateKey: privateKey,
		Peer: Peer{
			PublicKey:           publicKey,
			PresharedKey:        presharedKey,
			Endpoint:            endpoint,
			AllowedIPs:          allowedIPs,
			PersistentKeepalive: time.Duration(raw.Peer.PersistentKeepaliveSeconds) * time.Second,
		},
	}, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("expected exactly one JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func readSecret(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is required")
	}
	data, info, err := readRegularFile(path, 4096)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("secret file permissions must not grant access to group or other users")
	}
	if err := requireRootOwner(info); err != nil {
		return "", err
	}
	return string(data), nil
}

func readRegularFile(path string, limit int64) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("file must be a regular file, not a symlink or special file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, nil, fmt.Errorf("file changed while being opened")
	}
	if opened.Size() > limit {
		return nil, nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, opened, nil
}

func parseEndpoint(value string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("peer.endpoint must be an IP address and port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, fmt.Errorf("peer.endpoint host must be a specified unicast IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("peer.endpoint port must be between 1 and 65535")
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

func parsePrefixes(values []string, field string, rejectDefault bool) ([]net.IPNet, error) {
	prefixes := make([]net.IPNet, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		ip, prefix, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid CIDR %q: %w", field, value, err)
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("%s contains non-unicast prefix %q", field, value)
		}
		prefix.IP = ip
		ones, bits := prefix.Mask.Size()
		if rejectDefault && ones == 0 && (bits == 32 || bits == 128) {
			return nil, fmt.Errorf("%s must not contain default routes", field)
		}
		if rejectDefault {
			prefix.IP = prefix.IP.Mask(prefix.Mask)
		}
		ones, bits = prefix.Mask.Size()
		key := fmt.Sprintf("%s/%d", ip.String(), ones)
		if rejectDefault {
			key = fmt.Sprintf("%s/%d", prefix.IP.String(), ones)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%s contains duplicate prefix %q", field, value)
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, *prefix)
	}
	return prefixes, nil
}
