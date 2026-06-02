#!/usr/bin/env bash
# benches/throughput.sh — single-host SSTP tunnel throughput benchmark.
#
# Compares the kernel data path (sstp kmod + kTLS) vs the userspace
# TUN fallback by running iperf3 across a real SSTP tunnel between
# two endpoints on the same machine.
#
# Single-host topology (no extra hardware required):
#
#     ┌── host netns ──────────────────────────────────────────────┐
#     │  dev-radius  ──udp──┐                                       │
#     │                     ▼                                       │
#     │             sstp-server  (TCP/443, --data-path <mode>)      │
#     │                  pppN/tunN: 10.255.255.1                    │
#     │                  veth bench-h: 192.168.99.1                 │
#     │                  iperf3 server: bound to 10.255.255.1       │
#     └──────────────────────────│────────────────────────────────-─┘
#                                │  (veth pair)
#     ┌── netns sstpbench ───────│────────────────────────────────-─┐
#     │                  veth bench-c: 192.168.99.2                 │
#     │                  sstpc → 192.168.99.1:443                   │
#     │                  pppN: 10.99.0.42                           │
#     │                  iperf3 client → 10.255.255.1               │
#     └─────────────────────────────────────────────────────────────┘
#
# The veth pair carries the encrypted SSTP/TLS transport. Once the
# tunnel is up, iperf3 traffic between 10.99.0.42 (in-netns) and
# 10.255.255.1 (host) physically traverses the SSTP encapsulation
# instead of short-circuiting through `lo`, because each tunnel
# endpoint exists in only one of the two namespaces.
#
# Requirements (root):
#   * iperf3, sstpc (with pppd), ip, jq
#   * cargo / rustc (the script builds release binaries on demand)
#
# Usage:
#   sudo benches/throughput.sh [--mode kernel|tun|both] [--duration N]
#                              [--reverse] [--keep] [--shape RATE]
#
# Flags:
#   --mode          Which data path(s) to exercise (default: both).
#   --duration      iperf3 test duration in seconds (default: 10).
#   --reverse       Use iperf3 -R: receiver = client, sender = host.
#                   Default direction is client → host (uplink).
#   --parallel/-P N iperf3 parallel streams (default: 1).
#   --shape RATE    Apply a TBF qdisc to both ends of the veth pair
#                   capping the encrypted transport at RATE (e.g.
#                   100mbit, 1gbit). Empty = no shaping (default).
#                   When set, the script also runs a pre-tunnel
#                   baseline iperf3 across the bare veth to confirm
#                   the cap is enforced, and prints `tc -s qdisc`
#                   stats after each run.
#   --shape-burst B TBF burst (default: 32kbit). Bigger = more bursty.
#   --shape-latency T  TBF latency / queue depth (default: 50ms).
#   --rate-limit S  RADIUS-driven per-session shaping. S is the raw
#                   Mikrotik-Rate-Limit VSA value (vendor 14988,
#                   attr 8); dev-radius attaches it to Access-Accept,
#                   sstp-server installs HTB egress + ingress
#                   policing on the per-session pppN/tun netdev.
#                   Examples:
#                     --rate-limit 100M/50M        # 100 Mb rx, 50 Mb tx
#                     --rate-limit '50M 60M 50M 5' # rate burst-rate th burst-time
#                   The script verifies the qdisc landed on the
#                   server side and reports `tc -s qdisc dev <pppN>`
#                   stats alongside the iperf3 throughput.
#   --keep          Don't tear down on exit (useful for debugging;
#                   you must manually run --cleanup before re-running).
#   --cleanup       Tear down any leftover state and exit.
#
set -euo pipefail

# ----- defaults --------------------------------------------------------------
MODE=both
DURATION=10
REVERSE=
KEEP=
CLEANUP_ONLY=
PARALLEL=1
SHAPE=
SHAPE_BURST=32kbit
SHAPE_LATENCY=50ms
RATE_LIMIT=

# ----- arg parse -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)      MODE="$2"; shift 2 ;;
        --duration)  DURATION="$2"; shift 2 ;;
        --parallel|-P) PARALLEL="$2"; shift 2 ;;
        --reverse)   REVERSE=1; shift ;;
        --shape)     SHAPE="$2"; shift 2 ;;
        --shape-burst)   SHAPE_BURST="$2"; shift 2 ;;
        --shape-latency) SHAPE_LATENCY="$2"; shift 2 ;;
        --rate-limit)    RATE_LIMIT="$2"; shift 2 ;;
        --keep)      KEEP=1; shift ;;
        --cleanup)   CLEANUP_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,69p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

case "$MODE" in
    kernel|tun|both) ;;
    *) echo "--mode must be kernel|tun|both, got $MODE" >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (netns + pppd + /dev/sstp)" >&2
    exit 2
fi

# ----- paths -----------------------------------------------------------------
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS=sstpbench-cli
VETH_H=bench-h
VETH_C=bench-c
HOST_IP=192.168.99.1
NS_IP=192.168.99.2
SSTP_PORT=8443
RADIUS_PORT=11812
LOCAL_IP=10.255.255.1
FRAMED_IP=10.99.0.42
RUN_DIR="${TMPDIR:-/tmp}/sstpbench.$$"
SERVER_PID=
RADIUS_PID=
SSTPC_PID=
IPERF_S_PID=

# ----- prereq checks ---------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }
need ip
need iperf3
need jq

# Resolve sstpc; under sudo PATH is sanitised.
SSTPC=$(command -v sstpc || true)
if [[ -z "$SSTPC" ]]; then
    for d in "${HOME:-/root}/.local/bin" /usr/local/sbin /usr/sbin /sbin /opt/sstp-client/sbin; do
        [[ -x "$d/sstpc" ]] && SSTPC="$d/sstpc" && break
    done
fi
[[ -n "$SSTPC" ]] || { echo "sstpc not found on PATH" >&2; exit 2; }

[[ -e /dev/ppp ]] || { echo "/dev/ppp not present (needed by pppd in sstpc)" >&2; exit 2; }

# ----- cleanup ---------------------------------------------------------------
cleanup() {
    set +e
    [[ -n "$IPERF_S_PID" ]] && kill "$IPERF_S_PID" 2>/dev/null
    [[ -n "$SSTPC_PID"   ]] && ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null
    [[ -n "$SERVER_PID"  ]] && kill "$SERVER_PID" 2>/dev/null
    [[ -n "$RADIUS_PID"  ]] && kill "$RADIUS_PID" 2>/dev/null
    sleep 0.3
    [[ -n "$SERVER_PID"  ]] && kill -9 "$SERVER_PID" 2>/dev/null
    [[ -n "$RADIUS_PID"  ]] && kill -9 "$RADIUS_PID" 2>/dev/null
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip link del "$VETH_H" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    [[ -d "$RUN_DIR" && -z "$KEEP" ]] && rm -rf "$RUN_DIR"
    set -e
}
if [[ -n "$CLEANUP_ONLY" ]]; then
    cleanup
    echo "cleaned up"
    exit 0
fi
trap '[[ -z "$KEEP" ]] && cleanup' EXIT INT TERM

# ----- build -----------------------------------------------------------------
echo "==> building sstp-server + dev-radius (release)"
# Resolve cargo: under sudo, $PATH is sanitised AND rustup's active
# toolchain proxy can't resolve a default. Prefer a concrete
# toolchain binary under ~/.rustup/toolchains/*/bin/cargo.
CARGO=
for d in "${SUDO_USER:+/home/$SUDO_USER}/.rustup/toolchains" \
         "${HOME:-/root}/.rustup/toolchains"; do
    [[ -d "$d" ]] || continue
    for cand in "$d"/*/bin/cargo; do
        [[ -x "$cand" ]] && CARGO="$cand" && break 2
    done
done
[[ -n "$CARGO" ]] || CARGO=$(command -v cargo || true)
[[ -n "$CARGO" ]] || { echo "cargo not found" >&2; exit 2; }
# cargo needs rustc on PATH too.
export PATH="$(dirname "$CARGO"):$PATH"
( cd "$ROOT" && "$CARGO" build --release --bin sstp-server --example dev-radius ) >&2
SERVER_BIN="$ROOT/target/release/sstp-server"
RADIUS_BIN="$ROOT/target/release/examples/dev-radius"

mkdir -p "$RUN_DIR"
CERT="$RUN_DIR/cert.pem"
KEY="$RUN_DIR/key.pem"
SSTPC_PRIV="$RUN_DIR/sstpc-priv"
mkdir -p "$SSTPC_PRIV"

echo "==> generating self-signed cert"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=IP:$HOST_IP" \
    >/dev/null 2>&1

# ----- topology --------------------------------------------------------------
echo "==> setting up veth + netns"
# Wipe any leftover state from a previous run.
ip link del "$VETH_H" 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true

ip netns add "$NS"
ip link add "$VETH_H" type veth peer name "$VETH_C"
ip link set "$VETH_C" netns "$NS"
ip addr add "$HOST_IP/24" dev "$VETH_H"
ip link set "$VETH_H" up
ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$VETH_C"
ip netns exec "$NS" ip link set "$VETH_C" up
ip netns exec "$NS" ip link set lo up

# ----- shaping (optional) ----------------------------------------------------
# When --shape is set, install a TBF qdisc on each end of the veth
# pair so the encrypted transport is rate-limited symmetrically.
# Each direction is capped independently: bench-h's egress shapes
# server-→-client; bench-c's egress (inside the netns) shapes
# client-→-server. TBF gives a hard cap with predictable burst
# behaviour, which is what we want for verification — HTB / fq_codel
# would mask kmod issues behind smarter scheduling.
if [[ -n "$SHAPE" ]]; then
    need tc
    echo "==> shaping veth pair: rate=$SHAPE burst=$SHAPE_BURST latency=$SHAPE_LATENCY"
    tc qdisc add dev "$VETH_H" root tbf \
        rate "$SHAPE" burst "$SHAPE_BURST" latency "$SHAPE_LATENCY"
    ip netns exec "$NS" tc qdisc add dev "$VETH_C" root tbf \
        rate "$SHAPE" burst "$SHAPE_BURST" latency "$SHAPE_LATENCY"

    # Baseline: iperf3 directly across the bare veth (no SSTP) to
    # confirm TBF is actually enforcing the cap. If this number
    # isn't within ~5% of the requested rate, the cap is wrong
    # (kernel without sch_tbf, ridiculous burst, etc.) and any
    # downstream comparison is meaningless.
    echo "==> shaping baseline (bare veth, no tunnel)"
    iperf3 -s -B "$HOST_IP" -1 -p 5300 >"$RUN_DIR/iperf-baseline.log" 2>&1 &
    baseline_pid=$!
    sleep 0.3
    if ip netns exec "$NS" iperf3 -c "$HOST_IP" -p 5300 -t 5 -J \
            ${REVERSE:+-R} >"$RUN_DIR/iperf-baseline.json" 2>&1; then
        bl_sent=$(jq -r '.end.sum_sent.bits_per_second' \
            "$RUN_DIR/iperf-baseline.json")
        bl_mbps=$(awk "BEGIN{printf \"%.1f\", $bl_sent / 1e6}")
        echo "  baseline (bare veth): $bl_mbps Mb/s"
    else
        echo "  WARNING: baseline iperf3 failed" >&2
        cat "$RUN_DIR/iperf-baseline.json" >&2 || true
    fi
    kill "$baseline_pid" 2>/dev/null || true
    wait "$baseline_pid" 2>/dev/null || true
fi

# Reset qdisc counters so each run's `tc -s qdisc` reflects only
# that run's traffic. (TBF doesn't expose a reset op; replace
# rebuilds the qdisc with zeroed stats.)
shape_reset_counters() {
    [[ -z "$SHAPE" ]] && return 0
    tc qdisc replace dev "$VETH_H" root tbf \
        rate "$SHAPE" burst "$SHAPE_BURST" latency "$SHAPE_LATENCY"
    ip netns exec "$NS" tc qdisc replace dev "$VETH_C" root tbf \
        rate "$SHAPE" burst "$SHAPE_BURST" latency "$SHAPE_LATENCY"
}

shape_report() {
    [[ -z "$SHAPE" ]] && return 0
    echo "  tc -s qdisc dev $VETH_H (host egress, server→client):"
    tc -s qdisc show dev "$VETH_H" | sed 's/^/    /'
    echo "  tc -s qdisc dev $VETH_C (netns egress, client→server):"
    ip netns exec "$NS" tc -s qdisc show dev "$VETH_C" | sed 's/^/    /'
}

# ----- helpers ---------------------------------------------------------------
wait_for_ifname_in_ns() {
    # Poll for an interface with local addr = $FRAMED_IP inside $NS.
    local deadline=$(( SECONDS + 30 ))
    while (( SECONDS < deadline )); do
        local name
        name=$(ip netns exec "$NS" ip -o -4 addr show \
                 | awk -v ip="$FRAMED_IP" '$0 ~ "inet "ip" " { print $2; exit }')
        if [[ -n "$name" ]]; then echo "$name"; return 0; fi
        sleep 0.2
    done
    return 1
}

run_one() {
    local data_path="$1"
    echo
    echo "============================================================"
    echo "  data-path: $data_path"
    echo "============================================================"

    # ----- dev-radius ----
    local radius_extra=()
    [[ -n "$RATE_LIMIT" ]] && radius_extra+=(--rate-limit "$RATE_LIMIT")
    "$RADIUS_BIN" -l "127.0.0.1:$RADIUS_PORT" -p "10.99.0.42-10.99.0.42" \
        -u "alice:hunter2" "${radius_extra[@]}" \
        >"$RUN_DIR/radius.log" 2>&1 &
    RADIUS_PID=$!
    sleep 0.3

    # ----- sstp-server ----
    SSTP_RADIUS_SECRET=testing123 "$SERVER_BIN" \
        --listen "$HOST_IP:$SSTP_PORT" \
        --cert "$CERT" --key "$KEY" \
        --radius "127.0.0.1:$RADIUS_PORT" \
        --local-ip "$LOCAL_IP" \
        --data-path "$data_path" \
        --no-control-socket \
        -vv >"$RUN_DIR/server-$data_path.log" 2>&1 &
    SERVER_PID=$!

    # Wait for listener.
    local deadline=$(( SECONDS + 5 ))
    until ss -ltn "sport = :$SSTP_PORT" 2>/dev/null | grep -q LISTEN; do
        (( SECONDS >= deadline )) && { echo "server failed to listen"; cat "$RUN_DIR/server-$data_path.log"; return 1; }
        sleep 0.1
    done

    # ----- sstpc inside netns ----
    ip netns exec "$NS" "$SSTPC" \
        --cert-warn --save-server-route --log-stderr --log-level 2 \
        --priv-dir "$SSTPC_PRIV" \
        --user alice --password hunter2 \
        "$HOST_IP:$SSTP_PORT" \
        -- noauth noipdefault nodefaultroute \
           user alice password hunter2 \
        >"$RUN_DIR/sstpc-$data_path.log" 2>&1 &
    SSTPC_PID=$!

    echo "  waiting for client pppN with $FRAMED_IP..."
    local cli_if
    if ! cli_if=$(wait_for_ifname_in_ns); then
        echo "  ERROR: client pppN did not appear within 30s" >&2
        echo "  --- server log tail ---"
        tail -40 "$RUN_DIR/server-$data_path.log" >&2
        echo "  --- sstpc log tail ---"
        tail -40 "$RUN_DIR/sstpc-$data_path.log" >&2
        return 1
    fi
    echo "  client interface: $cli_if (in netns $NS)"

    # Server-side ifname (pppN or tunN) for diagnostics. Logs are
    # JSON; the bring-up info line carries both `ifname` and
    # `kernel_path`, which is the authoritative signal for which
    # data path is actually in use (the binary may silently fall
    # back to TUN under `--data-path auto`). The message string is
    # `"data path ready"` (was `"kernel PPP unit attached"` before
    # the kmod / TUN backends were unified — the unified message
    # covers both paths and surfaces `kernel_path=true|false`).
    local srv_if= srv_kpath=
    local deadline2=$(( SECONDS + 10 ))
    local attach_line=
    while (( SECONDS < deadline2 )); do
        attach_line=$(grep -m1 '"data path ready"' \
            "$RUN_DIR/server-$data_path.log" 2>/dev/null || true)
        [[ -n "$attach_line" ]] && break
        sleep 0.2
    done
    if [[ -n "$attach_line" ]]; then
        srv_if=$(jq -r '.fields.ifname // empty' <<<"$attach_line" 2>/dev/null || true)
        srv_kpath=$(jq -r '.fields.kernel_path // empty' <<<"$attach_line" 2>/dev/null || true)
    fi
    echo "  server interface: ${srv_if:-?} (kernel_path=${srv_kpath:-?})"

    # Verify the data path we asked for is what we got.
    case "$data_path" in
        kernel)
            if [[ "$srv_kpath" != "true" ]]; then
                echo "  ERROR: --data-path=kernel but kernel_path=$srv_kpath in attach line" >&2
                if grep -q 'kernel data path unavailable' \
                        "$RUN_DIR/server-$data_path.log"; then
                    echo "  (sstp-server fell back to TUN — check /dev/sstp + module)" >&2
                fi
                tail -40 "$RUN_DIR/server-$data_path.log" >&2
                return 1
            fi
            ;;
        tun)
            if [[ "$srv_kpath" != "false" || "$srv_if" != tun* ]]; then
                echo "  WARNING: --data-path=tun but srv_if=$srv_if kernel_path=$srv_kpath" >&2
            fi
            ;;
    esac

    # Give pppd a brief settling window after the netdev appears.
    sleep 0.5

    # If a RADIUS rate-limit is in effect, verify the qdisc landed
    # on the server-side netdev. The shaper installs HTB on egress
    # and the ingress qdisc + police filter on ingress; either
    # showing up confirms shape::Shaper::apply succeeded. Logged
    # before iperf3 so a misconfigured shape is caught up front.
    if [[ -n "$RATE_LIMIT" && -n "$srv_if" ]]; then
        echo "  RADIUS rate-limit: $RATE_LIMIT"
        echo "  tc qdisc show dev $srv_if (after Access-Accept):"
        tc qdisc show dev "$srv_if" | sed 's/^/    /'
        if ! tc qdisc show dev "$srv_if" | grep -qE 'htb|ingress'; then
            echo "  WARNING: no htb/ingress qdisc on $srv_if — shape::apply may have failed" >&2
            grep -iE 'shap|htb|ingress|mikrotik' \
                "$RUN_DIR/server-$data_path.log" | tail -10 >&2 || true
        fi
    fi

    # ----- iperf3 measurement ----
    iperf3 -s -B "$LOCAL_IP" -1 -p 5201 >"$RUN_DIR/iperf-s-$data_path.log" 2>&1 &
    IPERF_S_PID=$!
    sleep 0.3

    local iperf_extra=()
    [[ -n "$REVERSE" ]] && iperf_extra+=(-R)
    [[ "$PARALLEL" -gt 1 ]] && iperf_extra+=(-P "$PARALLEL")
    local json="$RUN_DIR/iperf-c-$data_path.json"
    if ! ip netns exec "$NS" iperf3 -c "$LOCAL_IP" -p 5201 \
            -t "$DURATION" -J "${iperf_extra[@]}" >"$json" 2>"$RUN_DIR/iperf-c-$data_path.err"
    then
        echo "  iperf3 client failed:" >&2
        cat "$RUN_DIR/iperf-c-$data_path.err" >&2
        return 1
    fi

    # Parse JSON: end.sum_sent and end.sum_received are bits/sec.
    local sent recv retx cpu_local cpu_remote
    sent=$(jq -r '.end.sum_sent.bits_per_second' "$json")
    recv=$(jq -r '.end.sum_received.bits_per_second' "$json")
    retx=$(jq -r '.end.sum_sent.retransmits // 0' "$json")
    cpu_local=$(jq -r '.end.cpu_utilization_percent.host_total' "$json")
    cpu_remote=$(jq -r '.end.cpu_utilization_percent.remote_total' "$json")

    local mbps_sent mbps_recv
    mbps_sent=$(awk "BEGIN{printf \"%.1f\", $sent / 1e6}")
    mbps_recv=$(awk "BEGIN{printf \"%.1f\", $recv / 1e6}")

    printf "  result: sent=%s Mb/s  recv=%s Mb/s  retx=%s  cpu_cli=%.1f%%  cpu_srv=%.1f%%\n" \
        "$mbps_sent" "$mbps_recv" "$retx" "$cpu_local" "$cpu_remote"

    shape_report

    # If RADIUS shaping was requested, dump the per-session qdisc
    # stats: HTB on egress shows sent/dropped/overlimits, ingress
    # police shows drops on overrate. These are the authoritative
    # signal that the kernel is enforcing the cap.
    if [[ -n "$RATE_LIMIT" && -n "$srv_if" ]]; then
        echo "  tc -s qdisc show dev $srv_if (after iperf3):"
        tc -s qdisc show dev "$srv_if" | sed 's/^/    /'
        echo "  tc -s class show dev $srv_if:"
        tc -s class show dev "$srv_if" 2>/dev/null | sed 's/^/    /'
        echo "  tc -s filter show dev $srv_if ingress:"
        tc -s filter show dev "$srv_if" ingress 2>/dev/null | sed 's/^/    /'
    fi

    # Stash for the comparison summary at the end.
    eval "RESULT_${data_path}_sent=$mbps_sent"
    eval "RESULT_${data_path}_recv=$mbps_recv"
    eval "RESULT_${data_path}_retx=$retx"
    eval "RESULT_${data_path}_ifname=${srv_if:-?}"

    # Tear down the per-run processes; netns + veth stay.
    kill "$IPERF_S_PID" 2>/dev/null || true; IPERF_S_PID=
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    SSTPC_PID=
    kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=
    kill "$RADIUS_PID" 2>/dev/null || true; wait "$RADIUS_PID" 2>/dev/null || true; RADIUS_PID=
    sleep 0.3
}

# ----- run -------------------------------------------------------------------
run_one_with_reset() {
    shape_reset_counters
    run_one "$1"
}
case "$MODE" in
    kernel) run_one_with_reset kernel ;;
    tun)    run_one_with_reset tun ;;
    both)
        run_one_with_reset tun
        run_one_with_reset kernel
        ;;
esac

# ----- summary ---------------------------------------------------------------
if [[ "$MODE" == both ]]; then
    echo
    echo "============================================================"
    echo "  Summary  (duration ${DURATION}s, ${REVERSE:+reverse }$( [[ -z $REVERSE ]] && echo client→host ))"
    echo "============================================================"
    printf "  %-7s  %10s  %10s  %8s  %s\n" mode "sent Mb/s" "recv Mb/s" "retx" "ifname"
    for m in tun kernel; do
        s=$(eval echo \${RESULT_${m}_sent})
        r=$(eval echo \${RESULT_${m}_recv})
        x=$(eval echo \${RESULT_${m}_retx})
        i=$(eval echo \${RESULT_${m}_ifname})
        printf "  %-7s  %10s  %10s  %8s  %s\n" "$m" "$s" "$r" "$x" "$i"
    done
    speedup=$(awk "BEGIN{printf \"%.2f\", $RESULT_kernel_sent / $RESULT_tun_sent}")
    echo
    echo "  kernel/tun speedup (sent): ${speedup}x"
fi

echo
echo "  logs: $RUN_DIR"
[[ -z "$KEEP" ]] || echo "  (kept; run '$0 --cleanup' to tear down)"
