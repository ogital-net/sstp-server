# benches/

Throughput benchmark for the SSTP tunnel data path.

## throughput.sh

Single-host A/B benchmark comparing `--data-path kernel` (sstp kmod
+ kTLS) against `--data-path tun` (userspace fallback). Uses
network namespaces so each tunnel endpoint exists in only one
namespace — without isolation, Linux short-circuits traffic
between two locally-assigned addresses through `lo` instead of
sending it through the SSTP tunnel.

Topology:

```
  host netns ───────────────── veth ───── netns sstpbench-cli
    sstp-server               192.168.99    sstpc + pppd
    iperf3 -s @10.255.255.1                 iperf3 -c → 10.255.255.1
    pppN/tunN: 10.255.255.1                 pppN: 10.99.0.42
```

The veth pair carries the encrypted SSTP/TLS transport on
`192.168.99.0/24`; iperf3 traffic on `10.99.0.42 ↔ 10.255.255.1`
physically traverses the tunnel.

### Requirements

Root, plus `iperf3`, `sstpc` (sstp-client), `ip`, `jq`, and a
toolchain that can build the workspace. For the kernel path the
sstp kmod must be loaded (`/dev/sstp` present) and the negotiated
TLS cipher must be kTLS-eligible (default config: TLS 1.3
AES-GCM; that's what the script's self-signed RSA cert produces).

### Usage

```bash
sudo benches/throughput.sh                    # both paths, 10s each
sudo benches/throughput.sh --duration 30      # longer run
sudo benches/throughput.sh --mode kernel      # just the kmod path
sudo benches/throughput.sh --mode tun         # just userspace
sudo benches/throughput.sh --reverse          # host → client (downlink)
sudo benches/throughput.sh --keep             # keep state for inspection
sudo benches/throughput.sh --cleanup          # tear down a kept run
```

### Reading the output

Each run prints sender + receiver Mb/s, retransmit count, and CPU
% on both ends. The comparison block at the end shows the
kernel/tun speedup.

Caveats:

- This is **localhost throughput**, dominated by memcpy bandwidth
  and TCP loopback acks rather than NIC speed. The absolute
  numbers are not representative of WAN deployment; the
  **ratio** between kernel and tun is what's interesting.
- The kmod path skips a userspace context-switch + memcpy + AEAD
  per packet. On a well-tuned modern x86_64 box expect roughly a
  1.5–3× ratio depending on CPU, kernel version, and whether
  AES-NI is hot. ChaCha20 is closer.
- TUN path performance is sensitive to whether `tcp-segmentation-offload`
  / `gso` are enabled on `tunN`. Default kernel settings apply.

## rekey-soak.sh

Repeatable, semi-automated soak for the TLS 1.3 rekey path. Same
single-host topology as `throughput.sh`, but instead of measuring
bulk throughput it loops the control-socket `rekey session <id>`
knob while a continuous ping flows through the tunnel and asserts
the session, the counters, and the data plane all stay healthy.

```bash
sudo benches/rekey-soak.sh                       # 20 rekeys, 2s apart, TUN
sudo benches/rekey-soak.sh --iterations 200      # longer run
sudo benches/rekey-soak.sh --request             # peer KeyUpdate too (RX path)
sudo benches/rekey-soak.sh --mode kernel         # v0.3: asserts the warn-
                                                 #       and-ignore contract
                                                 # v0.4+: real kmod rekey
sudo benches/rekey-soak.sh --cleanup             # tear down leftover state
```

Pass criteria (script exits 0 only when all are met):

- Every `rekey session <id>` returns `Rekey queued`.
- The session is still listed in `show sess` at the end.
- Background ping loss stays below `--loss-threshold` (default 5%).
- `sstp_session_teardown_rekey_{handshake,alert,other}` and
  `sstp_session_panics` do not advance.

This is the regression script the kmod rekey work
(`SSTP_IOC_KEYUPDATE_TX/RX`, UAPI v0.4) will be validated against:
the `--mode kernel` branch already runs end-to-end today, it just
exercises the v0.3 warn-and-reject contract instead of a real
rekey. When the new ioctls land, the kmod-side wiring in
`drive_sstp` flips from "log warn" to "issue ioctl", and the same
script becomes a real soak test for the kernel rekey FSM
(`src/crypto/rekey.rs`).
