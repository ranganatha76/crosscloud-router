# crosscloud-router

A Linux node agent for a **single, config-managed WireGuard tunnel**. It creates
a dedicated WireGuard interface, configures one peer, installs routes for that
peer's allowed IP ranges, and removes the interface when stopped.

This is a single-path node agent, not a claim of production certification.
There is no SaaS control plane, cloud route-table automation, HA/failover,
multi-peer management, or throughput guarantee. eBPF/XDP is intentionally not
in the packet path: WireGuard supplies the encrypted tunnel, while XDP alone
does not.

See [`DESIGN.md`](./DESIGN.md) for the problem statement, proposed architecture,
packet flow, lifecycle sequence, trust boundaries, and production acceptance
gates.

## Requirements

- Linux with WireGuard kernel support
- Go 1.26+ to build
- Root privileges to create the interface and routes (the supplied systemd
  unit limits the service to `CAP_NET_ADMIN`)
- Root-owned configuration and private key files (the agent verifies ownership
  when run as root)
- Network/firewall rules allowing the peer's UDP listen port
- Linux WireGuard kernel module available before the service starts

## Configuration

Copy [`config.example.json`](./config.example.json) to a root-owned location
such as `/etc/crosscloud-router/node.json`. Put a WireGuard private key in a
separate file readable only by root (`chmod 600`). Generate keys with the
standard WireGuard tools; never commit private keys.

The `addresses` are this node's tunnel addresses. `peer.allowed_ips` are the
remote tunnel and private network prefixes that should route through the peer.
Default routes are rejected to avoid unexpectedly diverting all host traffic.
`mtu` defaults to 1420 in the example and must be chosen below the effective
underlay path MTU after WireGuard overhead. The correct value depends on the
cloud network and outer IP family; validate it with real traffic and
path-MTU/fragmentation tests.
Cloud VPC/VNet routes must separately direct those remote prefixes to this
router VM. To forward traffic between cloud networks, enable IP forwarding and
install an appropriately scoped host firewall policy on both nodes. The
optional sysctl example is in [`deploy/sysctl/90-crosscloud-router.conf`](./deploy/sysctl/90-crosscloud-router.conf);
it changes forwarding globally and must not be enabled without a firewall
policy. Cloud security groups/NSGs must also allow the WireGuard UDP port
between the peer endpoints and the intended transit traffic.

## Validate and run

```sh
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go build -o router-agent ./cmd/router-agent
sudo ./router-agent --config /etc/crosscloud-router/node.json --check
sudo ./router-agent --config /etc/crosscloud-router/node.json
```

Build releases with the latest security-patched Go 1.26 toolchain; the CI
workflow runs tests, static checks, and the Go vulnerability scanner.

The agent refuses to take over an interface that already exists. On `SIGINT`
or `SIGTERM`, it removes routes installed by the agent and deletes its tunnel
interface. A stale interface is recovered on restart only if it bears the
agent's ownership alias. The agent checks interface, peer, and owned-route
state every 30 seconds; it restores a down interface or missing route when
safe, and logs/retries other local health failures without tearing down the
tunnel. A missing configured peer is re-applied from local configuration.
WireGuard handles handshake retries itself. Health logs include the last
handshake age and peer byte counters; a handshake timestamp alone is not
treated as proof of failure because idle peers need not handshake continuously.
Forward these logs to the operator's monitoring system; the agent does not
currently export a remote health endpoint or actively probe application paths.
A systemd unit template is provided in
[`deploy/systemd/crosscloud-router@.service`](./deploy/systemd/crosscloud-router@.service);
install the binary at `/usr/local/sbin/router-agent`, place the unit at
`/etc/systemd/system/crosscloud-router@.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now crosscloud-router@node
sudo journalctl -u crosscloud-router@node -f
```

The unit performs config validation before startup, restarts on process failure,
and limits restart bursts. Verify the unit's capability restrictions on the
target systemd version before deployment.

The agent rejects an exact destination route that already exists before
creating the tunnel. Resolve route ownership/table conflicts explicitly; it
does not delete or overwrite pre-existing routes.

### Operator-driven key rotation

1. Coordinate the new node public key with the remote operator and update the
   reciprocal peer configuration.
2. Replace the local private key file atomically with a root-owned mode-0600
   file. Update the optional preshared key file on both sides at the same time.
3. Reload the service using `systemctl reload crosscloud-router@node`.

SIGHUP reloads only local private/preshared keys. Changes to addresses,
endpoint, peer identity, routes, or listen port are rejected and require a
service restart. A peer-key change involves both sides and may interrupt
traffic; there is no automated overlap/rollback.

## Deployment checklist before production traffic

- Configure the reciprocal peer with this node's public key and tunnel address.
- Configure cloud route tables, host forwarding, and least-privilege firewall
  rules on both sides.
- Load WireGuard support at boot, and permit the required UDP port.
- Run on the actual target kernels/VM types; test connectivity, route
  conflicts, tunnel restart/shutdown, SIGHUP key rotation, peer reachability,
  host forwarding, firewall policy, and recovery after process/VM restart.
- Benchmark the real transit path in both directions with `iperf3` and the
  actual workload's packet sizes/concurrency. For example, run `iperf3 -s` on
  a remote test host and `iperf3 -c <remote-test-ip> -P 4 -t 60 --json` from
  the other side. Also measure loss/latency under load and compare the tunnel
  path to the same-cloud baseline; do not infer line rate from a build or a
  single large-packet test.

The agent currently requires a numeric peer endpoint IP; it does not refresh
DNS records. An unclean process termination may leave its managed interface
until the next start, when the agent replaces it. The health checker does not
actively probe end-to-end application reachability and there is no second path
for failover. Do not deploy this version for unattended production traffic
until live tunnel, forwarding, firewall, restart, and performance tests have
passed on the target Linux distribution and cloud.
