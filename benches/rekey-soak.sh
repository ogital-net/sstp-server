#!/usr/bin/env bash
# benches/rekey-soak.sh — repeatable, semi-automated TLS 1.3 rekey
# soak test. Brings up the same single-host SSTP topology as
# `throughput.sh`, then loops the control-socket `rekey session
# <id>` knob while continuous traffic flows through the tunnel.
#
# The point: stress the rekey path without writing a Rust e2e
# harness for it. Today this exercises the userspace-libssl rekey
# path on `--data-path tun`. Once UAPI v0.4 lands and the kmod
# learns `SSTP_IOC_KEYUPDATE_TX/RX`, the same script (with
# `--mode kernel`) becomes the primary regression test for the
# kernel-side rekey FSM (`src/crypto/rekey.rs`).
#
# Single-host topology (identical to throughput.sh):
#
#     ┌── host netns ────────────────────────────────────────────┐
#     │  dev-radius                                              │
#     │  sstp-server (TCP/$SSTP_PORT, --control-socket=…)        │
#     │       pppN/tunN: 10.255.255.1   ←—— ping target          │
#     └──────────────│────────────────────────────────────────--─┘
#                    │  (veth pair carries TLS transport)
#     ┌── netns sstpbench-cli ──────────────────────────────────-┐
#     │  sstpc → 192.168.99.1:$SSTP_PORT                         │
#     │  pppN: 10.99.0.42 ─── ping → 10.255.255.1                │
#     └─────────────────────────────────────────────────────────-┘
#
# Pass criteria (printed at end, exit 0 on pass, 1 on fail):
#   * `rekey session <id>` returns "Rekey queued" each iteration
#     (TUN backend) or the documented kmod-not-yet-supported
#     warning (kernel backend, v0.3).
#   * Tunnel stays up across every iteration: ping loss < threshold
#     (default 5%), no `sstp_session_teardown_*` counter advances
#     except `clean` on graceful shutdown.
#   * No `tls_rekey_other` / `_alert` / `_handshake` teardowns
#     under v0.3 kmod path either (the script does not request a
#     rekey there; it just logs the warn).
#
# Requirements (root): ip, sstpc + pppd, ping, jq, socat, cargo.
#
# Usage:
#   sudo benches/rekey-soak.sh [--mode tun|kernel] [--iterations N]
#                              [--interval SEC] [--request]
#                              [--loss-threshold PCT] [--keep]
#                              [--cleanup]
#
# Flags:
#   --mode             tun (default; works today) or kernel (v0.3
#                      asserts the warn-and-reject path; v0.4+ will
#                      drive real kmod rekey).
#   --iterations N     Number of rekey rounds (default: 20).
#   --interval SEC     Seconds between rounds (default: 2).
#   --request          Pass `request` so the peer sends back a
#                      KeyUpdate too (exercises RX path; default off).
#   --loss-threshold   Max acceptable ping loss percent (default 5).
#   --keep             Don't tear down on exit.
#   --cleanup          Tear down leftover state and exit.
#
set -euo pipefail

# ----- defaults --------------------------------------------------------------
MODE=tun
ITERATIONS=20
INTERVAL=2
REQUEST=
LOSS_THRESHOLD=5
KEEP=
CLEANUP_ONLY=

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)             MODE="$2"; shift 2 ;;
        --iterations)       ITERATIONS="$2"; shift 2 ;;
        --interval)         INTERVAL="$2"; shift 2 ;;
        --request)          REQUEST=1; shift ;;
        --loss-threshold)   LOSS_THRESHOLD="$2"; shift 2 ;;
        --keep)             KEEP=1; shift ;;
        --cleanup)          CLEANUP_ONLY=1; shift ;;
        -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

case "$MODE" in tun|kernel) ;; *) echo "--mode must be tun|kernel" >&2; exit 2;; esac

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (netns + pppd)" >&2; exit 2
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
RUN_DIR="${TMPDIR:-/tmp}/sstp-rekey-soak.$$"
CTL_SOCK="$RUN_DIR/control.sock"
SERVER_PID=
RADIUS_PID=
SSTPC_PID=
PING_PID=

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }
need ip; need jq; need socat; need ping; need awk

SSTPC=$(command -v sstpc || true)
if [[ -z "$SSTPC" ]]; then
    for d in "${HOME:-/root}/.local/bin" /usr/local/sbin /usr/sbin /sbin /opt/sstp-client/sbin; do
        [[ -x "$d/sstpc" ]] && SSTPC="$d/sstpc" && break
    done
fi
[[ -n "$SSTPC" ]] || { echo "sstpc not found on PATH" >&2; exit 2; }
[[ -e /dev/ppp ]] || { echo "/dev/ppp not present" >&2; exit 2; }
if [[ "$MODE" == kernel ]]; then
    [[ -e /dev/sstp ]] || { echo "--mode kernel requires /dev/sstp (load sstp.ko)" >&2; exit 2; }
fi

# ----- cleanup ---------------------------------------------------------------
cleanup() {
    set +e
    [[ -n "$PING_PID"   ]] && kill "$PING_PID" 2>/dev/null
    [[ -n "$SSTPC_PID"  ]] && ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    [[ -n "$RADIUS_PID" ]] && kill "$RADIUS_PID" 2>/dev/null
    sleep 0.3
    [[ -n "$SERVER_PID" ]] && kill -9 "$SERVER_PID" 2>/dev/null
    [[ -n "$RADIUS_PID" ]] && kill -9 "$RADIUS_PID" 2>/dev/null
    ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip link del "$VETH_H" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    [[ -d "$RUN_DIR" && -z "$KEEP" ]] && rm -rf "$RUN_DIR"
    set -e
}
if [[ -n "$CLEANUP_ONLY" ]]; then cleanup; echo "cleaned up"; exit 0; fi
trap '[[ -z "$KEEP" ]] && cleanup' EXIT INT TERM

# ----- build (release) -------------------------------------------------------
echo "==> building sstp-server + dev-radius (release)"
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
export PATH="$(dirname "$CARGO"):$PATH"
( cd "$ROOT" && "$CARGO" build --release --bin sstp-server --example dev-radius ) >&2
SERVER_BIN="$ROOT/target/release/sstp-server"
RADIUS_BIN="$ROOT/target/release/examples/dev-radius"

mkdir -p "$RUN_DIR"
CERT="$RUN_DIR/cert.pem"
KEY="$RUN_DIR/key.pem"
SSTPC_PRIV="$RUN_DIR/sstpc-priv"
mkdir -p "$SSTPC_PRIV"

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=IP:$HOST_IP" >/dev/null 2>&1

# ----- topology --------------------------------------------------------------
echo "==> bringing up veth + netns"
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

# ----- dev-radius + sstp-server ----------------------------------------------
echo "==> launching dev-radius"
"$RADIUS_BIN" -l "127.0.0.1:$RADIUS_PORT" \
    -p "$FRAMED_IP-$FRAMED_IP" -u "alice:hunter2" \
    >"$RUN_DIR/radius.log" 2>&1 &
RADIUS_PID=$!
sleep 0.3

echo "==> launching sstp-server (--data-path $MODE, control socket $CTL_SOCK)"
SSTP_RADIUS_SECRET=testing123 "$SERVER_BIN" \
    --listen "$HOST_IP:$SSTP_PORT" \
    --cert "$CERT" --key "$KEY" \
    --radius "127.0.0.1:$RADIUS_PORT" \
    --local-ip "$LOCAL_IP" \
    --data-path "$MODE" \
    --control-socket "$CTL_SOCK" \
    -vv >"$RUN_DIR/server.log" 2>&1 &
SERVER_PID=$!

# Wait for the listener and the control socket. Both must be up
# before sstpc connects, so we don't race the first `show sess`.
deadline=$(( SECONDS + 5 ))
until ss -ltn "sport = :$SSTP_PORT" 2>/dev/null | grep -q LISTEN; do
    (( SECONDS >= deadline )) && { echo "server failed to listen"; tail -40 "$RUN_DIR/server.log" >&2; exit 1; }
    sleep 0.1
done
deadline=$(( SECONDS + 5 ))
until [[ -S "$CTL_SOCK" ]]; do
    (( SECONDS >= deadline )) && { echo "control socket never appeared"; tail -40 "$RUN_DIR/server.log" >&2; exit 1; }
    sleep 0.1
done

# `socat -t1` waits for a 1-second idle from the server before
# returning, which is enough for the line-oriented dispatcher to
# write its full response (including the trailing blank line).
ctl() { socat -t1 - "UNIX-CONNECT:$CTL_SOCK" <<<"$1"; }

# ----- sstpc inside netns ----------------------------------------------------
echo "==> launching sstpc in netns $NS"
ip netns exec "$NS" "$SSTPC" \
    --cert-warn --save-server-route --log-stderr --log-level 2 \
    --priv-dir "$SSTPC_PRIV" \
    --user alice --password hunter2 \
    "$HOST_IP:$SSTP_PORT" \
    -- noauth noipdefault nodefaultroute \
       user alice password hunter2 \
    >"$RUN_DIR/sstpc.log" 2>&1 &
SSTPC_PID=$!

# Wait for the client-side pppN.
echo "==> waiting for tunnel..."
deadline=$(( SECONDS + 30 ))
cli_if=
while (( SECONDS < deadline )); do
    cli_if=$(ip netns exec "$NS" ip -o -4 addr show 2>/dev/null \
              | awk -v ip="$FRAMED_IP" '$0 ~ "inet "ip" " { print $2; exit }')
    [[ -n "$cli_if" ]] && break
    sleep 0.2
done
[[ -n "$cli_if" ]] || { echo "client pppN never appeared"; tail -40 "$RUN_DIR/server.log" >&2; tail -40 "$RUN_DIR/sstpc.log" >&2; exit 1; }
echo "  client interface: $cli_if (in netns $NS)"

# Find the session id from `show sess`. Format is one row per
# session; the first field is the id.
sleep 0.5
session_id=$(ctl "show sess" | awk '$1 ~ /^[0-9]+$/ { print $1; exit }')
[[ -n "$session_id" ]] || { echo "could not parse session id from 'show sess'"; ctl "show sess"; exit 1; }
echo "  session id: $session_id"

# ----- background ping -------------------------------------------------------
# 5 pings/sec gives enough granularity to detect any per-rekey
# stall worse than ~200 ms while keeping the encrypted transport
# busy. Output is parsed at the end; -q for the summary only.
echo "==> starting background ping (10.255.255.1 from netns)"
ip netns exec "$NS" ping -i 0.2 -q "$LOCAL_IP" >"$RUN_DIR/ping.log" 2>&1 &
PING_PID=$!

# ----- snapshot teardown counters BEFORE the soak ----------------------------
parse_stat() { ctl "show stat" | awk -v k="$1" '$1==k":" { print $2; exit }'; }
before_clean=$(parse_stat sstp_session_teardown_clean)
before_admin=$(parse_stat sstp_session_teardown_admin)
before_handshake=$(parse_stat sstp_session_teardown_rekey_handshake)
before_alert=$(parse_stat sstp_session_teardown_rekey_alert)
before_other=$(parse_stat sstp_session_teardown_rekey_other)
before_panics=$(parse_stat sstp_session_panics)
echo "  before: clean=$before_clean admin=$before_admin rekey_hs=$before_handshake rekey_alert=$before_alert rekey_other=$before_other panics=$before_panics"

# ----- soak loop -------------------------------------------------------------
rekey_cmd="rekey session $session_id"
[[ -n "$REQUEST" ]] && rekey_cmd="$rekey_cmd request"

echo "==> rekey soak: $ITERATIONS iter × ${INTERVAL}s (cmd: '$rekey_cmd')"
ok=0; bad=0
for (( i=1; i<=ITERATIONS; i++ )); do
    resp=$(ctl "$rekey_cmd" | head -n1)
    case "$MODE" in
        tun)
            if [[ "$resp" == Rekey\ queued* ]]; then
                ok=$(( ok + 1 ))
            else
                bad=$(( bad + 1 ))
                echo "  iter $i: unexpected response: $resp" >&2
            fi
            ;;
        kernel)
            # v0.3: control handler logs the warn and replies with
            # "Rekey queued" too (the variant is sent to the session
            # task; the kmod-backend gate in drive_sstp logs the
            # rejection). When the kmod gains real rekey support
            # this branch can tighten to the same `Rekey queued`
            # check as TUN. For now we treat anything other than an
            # explicit error as success.
            if [[ "$resp" == Rekey\ queued* ]]; then
                ok=$(( ok + 1 ))
            else
                bad=$(( bad + 1 ))
                echo "  iter $i: unexpected response: $resp" >&2
            fi
            ;;
    esac
    printf "  iter %3d/%d: %s\n" "$i" "$ITERATIONS" "$resp"
    sleep "$INTERVAL"
done

# ----- collect ping stats ----------------------------------------------------
# Stop ping cleanly so it prints the summary; SIGINT triggers the
# stats dump in iputils.
kill -INT "$PING_PID" 2>/dev/null || true
wait "$PING_PID" 2>/dev/null || true
PING_PID=

loss=$(awk '/packet loss/ {
    for (i=1;i<=NF;i++) if ($i ~ /%/) { gsub("%","",$i); print $i; exit }
}' "$RUN_DIR/ping.log")
loss=${loss:-100}
rtt_line=$(awk '/^rtt|^round-trip/ { print; exit }' "$RUN_DIR/ping.log")

# ----- snapshot teardown counters AFTER --------------------------------------
after_clean=$(parse_stat sstp_session_teardown_clean)
after_admin=$(parse_stat sstp_session_teardown_admin)
after_handshake=$(parse_stat sstp_session_teardown_rekey_handshake)
after_alert=$(parse_stat sstp_session_teardown_rekey_alert)
after_other=$(parse_stat sstp_session_teardown_rekey_other)
after_panics=$(parse_stat sstp_session_panics)

# Session must still be live (we haven't sent disconnect yet).
sess_live=$(ctl "show sess" | awk -v id="$session_id" '$1==id { print "yes"; exit }')
sess_live=${sess_live:-no}

# Count the kmod-rejection warn lines for visibility.
kmod_warn=$(grep -c 'rekey rejected (kmod backend' "$RUN_DIR/server.log" || true)

# ----- report ----------------------------------------------------------------
echo
echo "============================================================"
echo "  Rekey soak result (mode=$MODE)"
echo "============================================================"
printf "  iterations:           %d (ok=%d bad=%d)\n" "$ITERATIONS" "$ok" "$bad"
printf "  ping loss:            %s%% (threshold %s%%)\n" "$loss" "$LOSS_THRESHOLD"
[[ -n "$rtt_line" ]] && echo "  $rtt_line"
printf "  session still up:     %s\n" "$sess_live"
printf "  teardown deltas:      clean=%d admin=%d rekey_hs=%d rekey_alert=%d rekey_other=%d panics=%d\n" \
    $(( after_clean - before_clean )) \
    $(( after_admin - before_admin )) \
    $(( after_handshake - before_handshake )) \
    $(( after_alert - before_alert )) \
    $(( after_other - before_other )) \
    $(( after_panics - before_panics ))
[[ "$MODE" == kernel ]] && printf "  kmod warn lines:      %s\n" "$kmod_warn"
echo "  logs: $RUN_DIR"

# Pass criteria.
fail=0
if (( bad != 0 )); then
    echo "  FAIL: $bad rekey commands returned unexpected responses" >&2
    fail=1
fi
if [[ "$sess_live" != yes ]]; then
    echo "  FAIL: session $session_id is gone after soak" >&2
    fail=1
fi
if awk -v l="$loss" -v t="$LOSS_THRESHOLD" 'BEGIN { exit !(l+0 > t+0) }'; then
    echo "  FAIL: ping loss $loss% exceeds threshold $LOSS_THRESHOLD%" >&2
    fail=1
fi
delta_bad=$(( (after_handshake - before_handshake) \
            + (after_alert     - before_alert) \
            + (after_other     - before_other) \
            + (after_panics    - before_panics) ))
if (( delta_bad != 0 )); then
    echo "  FAIL: rekey/panic teardown counters advanced during soak" >&2
    fail=1
fi
if [[ "$MODE" == kernel ]] && (( kmod_warn < ITERATIONS )); then
    echo "  WARN: kmod rejection log lines ($kmod_warn) < iterations ($ITERATIONS)" >&2
    # Not a hard fail — the warn-and-ignore wiring is the v0.3
    # contract; if the kmod ever ships real rekey, this expectation
    # flips and the comparison should change with it.
fi

if (( fail == 0 )); then
    echo "  PASS"
    exit 0
else
    echo "  --- server.log tail ---" >&2
    tail -60 "$RUN_DIR/server.log" >&2
    exit 1
fi
