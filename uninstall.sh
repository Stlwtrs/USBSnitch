#!/usr/bin/env bash
# Remove USBSnitch and its systemd service.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo ./uninstall.sh" >&2
  exit 1
fi

systemctl disable --now usb-snitch.service 2>/dev/null || true
rm -f /etc/systemd/system/usb-snitch.service /usr/local/bin/usb-snitch
systemctl daemon-reload
echo "[+] USBSnitch removed."
