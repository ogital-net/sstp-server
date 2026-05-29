#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Builds the kmod (if needed), loads it (if not already loaded),
# runs test_sstp as root, and reports.
#
# Run from kmod/tests/ via `make run`, or standalone with no args.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$(cd "$HERE/.." && pwd)"

KO="$KMOD/sstp.ko"
NAME="sstp"

say() { printf '== %s\n' "$*"; }

# 1. Ensure the kernel tls module is available (needed for kTLS).
if ! lsmod | grep -q '^tls '; then
	say "loading tls module"
	sudo -n modprobe tls
fi

# 2. Build kmod if missing or out of date.
if [[ ! -f "$KO" ]] || \
   [[ -n "$(find "$KMOD" -maxdepth 1 -name '*.c' -newer "$KO" -print -quit)" ]]; then
	say "building kmod"
	make -C "$KMOD" >/dev/null
fi

# 3. Load module if not loaded.
if ! lsmod | grep -q "^${NAME} "; then
	say "loading $NAME.ko"
	sudo -n insmod "$KO"
fi

# Confirm /dev/sstp came up.
if [[ ! -e /dev/sstp ]]; then
	echo "ERROR: /dev/sstp not present after insmod" >&2
	exit 1
fi

# 4. Build test program.
say "building test_sstp"
make -C "$HERE" test_sstp >/dev/null

# 5. Run as root.
say "running tests"
sudo -n "$HERE/test_sstp"
rc=$?

# 6. Show the last few kernel-log lines for diagnosis.
say "kernel log (last 10 lines)"
sudo -n dmesg | tail -10

# 7. Try rmmod to confirm clean unload after the run.
say "attempting rmmod $NAME"
if sudo -n rmmod "$NAME" 2>/dev/null; then
	echo "   rmmod ok"
else
	echo "   rmmod failed (sessions still referenced?) — leaving loaded"
fi

exit "$rc"
