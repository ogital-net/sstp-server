#!/usr/bin/env bash
# Dev container post-create hook.
#
# Installs system build dependencies and compiles the ndmsystems/sstp-client
# binary for use in integration / interop tests (so the test suite does not
# require a Windows or MikroTik client on the network).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    cmake \
    clang \
    libclang-dev \
    perl \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    libevent-dev \
    ppp \
    ppp-dev \
    iproute2 \
    iputils-ping \
    ca-certificates \
    git

SSTP_CLIENT_REPO="https://github.com/ndmsystems/sstp-client.git"
SSTP_CLIENT_REF="ndm-1.0.12"
SRC_DIR="/opt/sstp-client/src"
PREFIX="/opt/sstp-client"

sudo mkdir -p "$PREFIX"
sudo chown "$USER:$USER" "$PREFIX"

if [[ ! -x "$PREFIX/sbin/sstpc" && ! -x "$PREFIX/bin/sstpc" ]]; then
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$SSTP_CLIENT_REF" \
        "$SSTP_CLIENT_REPO" "$SRC_DIR"
    cd "$SRC_DIR"
    # The shipped configure is pinned to aclocal-1.14; regenerate the
    # build system against whatever automake the container provides.
    autoreconf -fi
    # Skip the pppd plugin: it references pppd 2.4.x-only internals
    # (path_ipup, add_options, ip_up_notifier, ...) that no longer
    # exist on Debian trixie's ppp 2.5.x. We only need the `sstpc`
    # client binary for interop testing.
    ./configure --prefix="$PREFIX" --disable-ppp-plugin
    make -j"$(nproc)"
    make install
fi

# Symlink for tests to discover via PATH without root.
mkdir -p "$HOME/.local/bin"
for bin in sstpc sstp-test sstp-state; do
    for d in "$PREFIX/sbin" "$PREFIX/bin"; do
        if [[ -x "$d/$bin" ]]; then
            ln -sf "$d/$bin" "$HOME/.local/bin/$bin"
        fi
    done
done

echo "sstp-client installed:"
ls -l "$HOME/.local/bin/" | grep sstp || true
"$HOME/.local/bin/sstpc" --version || true
