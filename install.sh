#!/usr/bin/env bash
# Install USBSnitch as a systemd service.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo ./install.sh" >&2
  exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
  echo "[-] USBSnitch needs Python 3.9 or newer." >&2
  exit 1
fi

if ! command -v notify-send >/dev/null 2>&1; then
  echo "[*] Installing notify-send (libnotify)..."
  if command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm libnotify
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get install -y libnotify-bin
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y libnotify
  else
    echo "[-] Install libnotify manually for desktop notifications; logging works without it."
  fi
fi

install -Dm755 usb-snitch.py /usr/local/bin/usb-snitch
install -Dm644 usb-snitch.service /etc/systemd/system/usb-snitch.service
systemctl daemon-reload

echo "[+] Installed. Start it now and on every boot with:"
echo "    sudo systemctl enable --now usb-snitch"
