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

id koine >/dev/null 2>&1 || useradd --system --home /var/lib/koine-mailbox --shell /usr/sbin/nologin koine
install -d -m 0750 -o koine -g koine /var/lib/koine-mailbox
install -d -m 0755 /opt/koine/mailbox
[ "$HERE" = /opt/koine/mailbox ] || install -m 0755 "$HERE/mailbox.py" /opt/koine/mailbox/mailbox.py
[ "$HERE" = /opt/koine/mailbox ] || install -m 0644 "$HERE/langfuse_emit.py" /opt/koine/mailbox/langfuse_emit.py
install -m 0644 "$HERE/koine-mailbox.service" /etc/systemd/system/koine-mailbox.service
# CERT_FILE/KEY_FILE in mailbox.env must be readable by the koine user (root:koine 640). With
# Let's Encrypt, copy the live cert into a service dir via a renewal deploy-hook (see README).

systemctl daemon-reload
systemctl enable --now koine-mailbox
sleep 1
PORT="$(. "$ENVFILE"; echo "${PUBLIC_PORT:-8443}")"
echo "health:"; curl -sk "https://127.0.0.1:${PORT}/health" || echo "(not up yet — check: journalctl -u koine-mailbox)"
echo
