#!/usr/bin/env bash
# Install koine-mailbox on a fresh Debian/Ubuntu host. Idempotent. Run as root.
# Prereqs you provide first: /etc/koine-mailbox/mailbox.env (see README) + cert.pem/key.pem there.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE=/etc/koine-mailbox/mailbox.env

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
[ -f "$ENVFILE" ] || { echo "missing $ENVFILE — create it first (see README.md)"; exit 1; }
chmod 600 "$ENVFILE"

install -d -m 0755 /opt/koine/mailbox
install -m 0755 "$HERE/mailbox.py" /opt/koine/mailbox/mailbox.py
install -m 0644 "$HERE/langfuse_emit.py" /opt/koine/mailbox/langfuse_emit.py
install -m 0644 "$HERE/koine-mailbox.service" /etc/systemd/system/koine-mailbox.service

systemctl daemon-reload
systemctl enable --now koine-mailbox
sleep 1
PORT="$(. "$ENVFILE"; echo "${PUBLIC_PORT:-8443}")"
echo "health:"; curl -sk "https://127.0.0.1:${PORT}/health" || echo "(not up yet — check: journalctl -u koine-mailbox)"
echo
