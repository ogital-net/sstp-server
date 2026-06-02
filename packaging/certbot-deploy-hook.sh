#!/bin/sh
# certbot deploy-hook for sstp-server.
#
# Copies the renewed Let's Encrypt cert + key into
# /etc/sstp-server/, fixes permissions so the daemon group can
# read them, and sends SIGHUP to the running daemon. SIGHUP
# reloads the TLS material in place — existing sessions keep
# running on the old SSL_CTX (refcount-protected), and only new
# TCP connections pick up the new certificate.
#
# Wire into certbot one of two ways:
#
#   1. Per-cert in renewal config
#      /etc/letsencrypt/renewal/<host>.conf:
#        [renewalparams]
#        deploy_hook = /usr/share/sstp-server/certbot-deploy-hook.sh
#
#   2. Global (applies to every renewed cert):
#        certbot renew --deploy-hook /usr/share/sstp-server/certbot-deploy-hook.sh
#
# certbot exports RENEWED_LINEAGE pointing at the
# /etc/letsencrypt/live/<name>/ directory of the cert that was
# just renewed; we use that to find fullchain.pem + privkey.pem.

set -eu

if [ -z "${RENEWED_LINEAGE:-}" ]; then
    echo "certbot-deploy-hook: RENEWED_LINEAGE unset; not running under certbot?" >&2
    exit 1
fi

DEST_DIR="${SSTP_CERT_DIR:-/etc/sstp-server}"
DEST_CERT="${DEST_DIR}/server.crt"
DEST_KEY="${DEST_DIR}/server.key"
GROUP="${SSTP_GROUP:-sstp-server}"
UNIT="${SSTP_UNIT:-sstp-server.service}"

install -m 0644 -o root -g "$GROUP" \
    "${RENEWED_LINEAGE}/fullchain.pem" "$DEST_CERT"
install -m 0640 -o root -g "$GROUP" \
    "${RENEWED_LINEAGE}/privkey.pem"   "$DEST_KEY"

# SIGHUP: reload TLS material without disrupting active sessions.
# `systemctl kill -s HUP` is preferred over `pkill` because it
# targets only the daemon's main PID and respects the unit's
# KillMode.
if systemctl is-active --quiet "$UNIT"; then
    systemctl kill -s HUP "$UNIT"
    echo "certbot-deploy-hook: reloaded TLS material in $UNIT"
else
    echo "certbot-deploy-hook: $UNIT not active; cert installed but no reload signalled"
fi
