# P4PVpn

P4PVpn is an IPv6 overlay VPN based on P4PCore. It derives each node's virtual
IPv6 address from its Ed25519 public key, discovers nodes with NodeGossiper,
authenticates connections with SecureNet, and forwards IPv6 packets through a
Linux TUN device. Only nodes listed in `vpnPeerNodes` or registered as
bootstrap nodes are accepted.

The complete configuration reference is
[config.json.example](./config.json.example). Use that file as the template
for all settings. The program creates the configuration, private-key, and
node-state files automatically when they do not exist.

`bootstrapNodes` contains the address and public key of nodes used for initial
discovery. `vpnPeerNodes` contains only the hexadecimal public keys of nodes
allowed to join the VPN. Peer addresses are learned through NodeGossiper or
the persisted node state.

The TUN interface name is configured with `tunName` in the JSON file or
`--tunName` on the command line; it defaults to `tun0`.

The [example/](./example/) directory contains a small Linux-only
`LinuxTunDevice` smoke test. It assigns a public-key-derived IPv6 address to a
TUN device and forwards packets for that address to `127.0.0.1`.

For development and packet-flow testing, start the TUN simulation GUI with
`--gui`:

```bash
python -m P4PVpn --gui
```

The GUI uses a simulated TUN device instead of `/dev/net/tun`. Enter a virtual
IPv6 destination and UTF-8 data, then select `TUN から送信` to exercise the
normal outbound routing path. Select `受信をシミュレート` to inject received
data into the normal inbound path and display what would be delivered to TUN.
The VPN still uses the configured NodeGossiper and SecureNet connections, so
outbound delivery requires the destination peer to be connected.

If `privateKey` is omitted, the program generates an Ed25519 private key on
first start and saves it to `privateKeyFile`. The saved key is reused on later
starts so the node's public key remains stable.

When `configFile` is not specified, `p4pvpn-config.json` is created
automatically in the current directory. An explicitly specified but missing
`configFile` is also created with the default settings.

## Linux binary

For every version tag, CI first runs the tests, builds the Python package, and
then compiles a single-file Linux x86_64 executable with Nuitka. The executable
is published directly as the `P4PVpn-linux-x86_64` asset on the GitHub Release;
it is not distributed as a tar.gz archive. The same Release also contains the
Python package artifacts.

Download the `P4PVpn-linux-x86_64` asset from the Release, make it executable,
and run it directly:

```bash
chmod +x P4PVpn-linux-x86_64
sudo ./P4PVpn-linux-x86_64
```

On its first start, the binary creates `p4pvpn-config.json`,
`p4pvpn-private-key`, and `p4pvpn-nodes.json` in the current directory.
Alternatively, copy [config.json.example](./config.json.example), edit the
settings, and pass it explicitly:

```bash
cp config.json.example p4pvpn-config.json
sudo ./P4PVpn-linux-x86_64 --configFile "$PWD/p4pvpn-config.json"
```

The executable is intended for Linux hosts because the VPN uses
`/dev/net/tun`. It uses the host's shared Python runtime interface, so it is
intended for compatible Linux systems rather than every Linux distribution
without dependencies.
