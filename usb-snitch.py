#!/usr/bin/env python3
"""
USBSnitch: real-time USB device alerts for Linux, built for USBGuard users.

When a USB device is connected, USBSnitch:
  1. receives the kernel's hotplug event over netlink,
  2. reads what the device says it is from sysfs, including its raw USB
     descriptors (available even when USBGuard has blocked the device),
  3. waits for the authorization decision (USBGuard or the kernel default),
  4. flags interface combinations used by attack tools such as BadUSB
     keystroke injectors and rogue network adapters, and
  5. logs the result and shows a desktop notification.

Standard library only. notify-send (libnotify) is used for notifications.
"""

import argparse
import json
import os
import pwd
import re
import select
import socket
import subprocess
import sys
import time

__version__ = "2.0.0"

SYSFS = "/sys"
RUN_USER = "/run/user"
USB_IDS_PATHS = ("/usr/share/hwdata/usb.ids", "/usr/share/misc/usb.ids", "/var/lib/usbutils/usb.ids")

NETLINK_KOBJECT_UEVENT = 15
KERNEL_EVENTS_GROUP = 1

# --------------------------------------------------------------------------
# USB descriptor parsing
# --------------------------------------------------------------------------

CLASS_NAMES = {
    0x01: "Audio", 0x02: "Communications", 0x03: "HID", 0x05: "Physical",
    0x06: "Image", 0x07: "Printer", 0x08: "Mass Storage", 0x09: "Hub",
    0x0A: "CDC Data", 0x0B: "Smart Card", 0x0D: "Content Security",
    0x0E: "Video", 0x0F: "Healthcare", 0x10: "Audio/Video", 0xDC: "Diagnostic",
    0xE0: "Wireless", 0xEF: "Miscellaneous", 0xFE: "Application Specific",
    0xFF: "Vendor Specific",
}

DESC_DEVICE = 0x01
DESC_INTERFACE = 0x04


def parse_descriptors(raw):
    """Parse the sysfs 'descriptors' blob into device and interface info.

    The blob holds the 18-byte device descriptor followed by the raw
    configuration descriptors. The kernel reads these while enumerating the
    device, before any authorization decision, so they describe what a
    blocked device *would* have exposed.
    """
    info = {"device_class": None, "vendor_id": None, "product_id": None, "interfaces": []}
    seen = set()
    i = 0
    while i + 2 <= len(raw):
        length, dtype = raw[i], raw[i + 1]
        if length < 2 or i + length > len(raw):
            break
        d = raw[i:i + length]
        if dtype == DESC_DEVICE and length >= 18:
            info["device_class"] = d[4]
            info["vendor_id"] = f"{d[8] | d[9] << 8:04x}"
            info["product_id"] = f"{d[10] | d[11] << 8:04x}"
        elif dtype == DESC_INTERFACE and length >= 9:
            key = (d[5], d[6], d[7])
            if key not in seen:
                seen.add(key)
                info["interfaces"].append({"class": d[5], "subclass": d[6], "protocol": d[7]})
        i += length
    return info


def describe_interface(itf):
    c, s, p = itf["class"], itf["subclass"], itf["protocol"]
    if c == 0x03:
        if s == 0x01 and p == 0x01:
            return "Keyboard"
        if s == 0x01 and p == 0x02:
            return "Mouse"
        return "HID (input device)"
    if is_network(itf):
        return "Network adapter"
    return CLASS_NAMES.get(c, f"Class 0x{c:02x}")


def is_keyboard_capable(itf):
    # Boot keyboards declare it; other HID devices may still send keystrokes,
    # which can't be known without parsing the HID report descriptor.
    return itf["class"] == 0x03 and not (itf["subclass"] == 0x01 and itf["protocol"] == 0x02)


def is_network(itf):
    c, s, p = itf["class"], itf["subclass"], itf["protocol"]
    return (
        (c == 0x02 and s in (0x06, 0x0A, 0x0D, 0x0E))   # CDC ECM, EEM, NCM, MBIM
        or (c == 0x02 and s == 0x02 and p == 0xFF)      # RNDIS (CDC variant)
        or (c == 0xE0 and s == 0x01 and p == 0x03)      # RNDIS (wireless class)
        or (c == 0xEF and s == 0x04 and p == 0x01)      # RNDIS (misc class)
    )


STORAGE_WORDS = re.compile(r"flash|disk|drive|storage|thumb|stick|memory|card", re.I)


def assess_risk(interfaces, product_name=""):
    """Return (level, reasons) for a device's interface set.

    Levels: "high", "medium", "low". These are heuristics for attention,
    not verdicts; plenty of legitimate hardware is a keyboard or a network
    adapter.
    """
    kbd = any(is_keyboard_capable(i) for i in interfaces)
    storage = any(i["class"] == 0x08 for i in interfaces)
    net = any(is_network(i) for i in interfaces)
    reasons = []

    if kbd and storage:
        reasons.append("combines a keyboard-capable interface with storage, a common BadUSB layout")
    if kbd and net:
        reasons.append("combines a keyboard-capable interface with a network adapter")
    if kbd and not storage and STORAGE_WORDS.search(product_name or ""):
        reasons.append(f"calls itself '{product_name}' but presents as a keyboard, not storage")
    if reasons:
        return "high", reasons

    if net:
        return "medium", ["adds a network adapter, which can redirect or capture traffic"]
    if kbd:
        return "medium", ["can type keystrokes; expected only if you plugged in a keyboard"]
    return "low", []


# --------------------------------------------------------------------------
# Device information from sysfs
# --------------------------------------------------------------------------

def _read(path, binary=False):
    try:
        with open(path, "rb" if binary else "r") as f:
            return f.read() if binary else f.read().strip()
    except OSError:
        return None


def sanitize(text, limit=64):
    """Device strings are attacker-controlled: strip control characters and cap length."""
    if not text:
        return ""
    text = "".join(ch if ch.isprintable() else "?" for ch in text)
    return text[:limit] + ("..." if len(text) > limit else "")


_usb_ids_cache = {}


def lookup_usb_ids(vendor_id, product_id, paths=USB_IDS_PATHS):
    """Look up vendor and product names in the usb.ids database, if installed."""
    key = (vendor_id, product_id)
    if key in _usb_ids_cache:
        return _usb_ids_cache[key]
    vendor = product = None
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                in_vendor = False
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    if not line[0].isspace():
                        if in_vendor:
                            break
                        if line[:4].lower() == vendor_id:
                            vendor, in_vendor = line[4:].strip(), True
                        elif line.startswith("C "):  # class list follows the vendor list
                            break
                    elif in_vendor and line.startswith("\t") and not line.startswith("\t\t"):
                        if line[1:5].lower() == product_id:
                            product = line[5:].strip()
                            break
            break
        except OSError:
            continue
    _usb_ids_cache[key] = (vendor, product)
    return vendor, product


def read_device(devpath, sysfs=SYSFS):
    """Collect everything USBSnitch reports about one USB device."""
    base = os.path.join(sysfs, devpath.lstrip("/"))
    raw = _read(os.path.join(base, "descriptors"), binary=True) or b""
    desc = parse_descriptors(raw)

    vid = (_read(os.path.join(base, "idVendor")) or desc["vendor_id"] or "????").lower()
    pid = (_read(os.path.join(base, "idProduct")) or desc["product_id"] or "????").lower()
    db_vendor, db_product = lookup_usb_ids(vid, pid)
    manufacturer = sanitize(_read(os.path.join(base, "manufacturer")))
    product = sanitize(_read(os.path.join(base, "product")))

    interfaces = desc["interfaces"]
    level, reasons = assess_risk(interfaces, product)
    return {
        "devpath": devpath,
        "port": os.path.basename(devpath),
        "id": f"{vid}:{pid}",
        "vendor": db_vendor or manufacturer or "Unknown vendor",
        "product": product or db_product or "Unknown device",
        "manufacturer_reported": manufacturer,
        "product_reported": product,
        "serial": sanitize(_read(os.path.join(base, "serial"))),
        "interfaces": [describe_interface(i) for i in interfaces],
        "risk": level,
        "reasons": reasons,
        "_base": base,
    }


def read_authorized(base):
    value = _read(os.path.join(base, "authorized"))
    if value is None:
        return None
    return value == "1"


def wait_for_decision(base, timeout, interval=0.1, clock=time.monotonic, sleep=time.sleep):
    """Wait for the authorization decision.

    With USBGuard, a new device starts unauthorized (0) and the daemon then
    allows (1) it, leaves it blocked, or rejects it (the device disappears).
    Authorization is final once it reads 1; otherwise the state at the end
    of the timeout is reported.
    """
    deadline = clock() + timeout
    while True:
        state = read_authorized(base)
        if state is None:
            return "rejected"
        if state:
            return "allowed"
        if clock() >= deadline:
            return "blocked"
        sleep(interval)


# --------------------------------------------------------------------------
# Notifications: no shell, drop to the session user's own privileges
# --------------------------------------------------------------------------

def escape_markup(text):
    """notify-send bodies may be rendered as markup; escape device-supplied text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def find_sessions(run_user=RUN_USER, only=None):
    """Return (uid, gid, name, bus_path) for each user with a session bus."""
    sessions = []
    try:
        entries = sorted(os.listdir(run_user))
    except OSError:
        return sessions
    for entry in entries:
        if not entry.isdigit():
            continue
        bus = os.path.join(run_user, entry, "bus")
        if not os.path.exists(bus):
            continue
        try:
            pw = pwd.getpwuid(int(entry))
        except KeyError:
            continue
        if pw.pw_uid == 0 or (only and pw.pw_name not in only):
            continue
        if os.geteuid() != 0 and pw.pw_uid != os.geteuid():
            continue  # without root, only our own session bus is reachable
        sessions.append((pw.pw_uid, pw.pw_gid, pw.pw_name, bus))
    return sessions


def notification_for(event):
    status = event["status"]
    title = f"USB {status}: {event['product']}"
    lines = [
        f"{event['vendor']} ({event['id']}) on port {event['port']}",
        "Interfaces: " + (", ".join(event["interfaces"]) or "none reported"),
    ]
    if event["risk"] != "low":
        lines.append(f"Risk: {event['risk'].upper()}, " + "; ".join(event["reasons"]))
    urgency = "critical" if status != "allowed" or event["risk"] == "high" else "normal"
    icon = "dialog-error" if urgency == "critical" else "drive-removable-media"
    return title, "\n".join(lines), urgency, icon


def send_notifications(event, sessions, run=subprocess.run):
    title, body, urgency, icon = notification_for(event)
    title, body = escape_markup(title), escape_markup(body)
    for uid, gid, name, bus in sessions:
        cmd = ["notify-send", "--app-name=USBSnitch", "-u", urgency, "-i", icon, title, body]
        env = {
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
            "XDG_RUNTIME_DIR": os.path.dirname(bus),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        kwargs = {"env": env, "timeout": 5, "check": False,
                  "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if os.geteuid() == 0:
            kwargs.update(user=uid, group=gid, extra_groups=[])
        try:
            run(cmd, **kwargs)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"[-] Notification to {name} failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------
# Kernel events
# --------------------------------------------------------------------------

def parse_uevent(data):
    """Parse a kernel uevent datagram ("action@devpath\\0KEY=VALUE\\0...")."""
    parts = data.split(b"\0")
    if not parts or b"@" not in parts[0]:
        return None
    event = {}
    for part in parts[1:]:
        key, sep, value = part.partition(b"=")
        if sep:
            event[key.decode(errors="replace")] = value.decode(errors="replace")
    return event


def is_usb_device_event(event):
    return (event is not None and event.get("SUBSYSTEM") == "usb"
            and event.get("DEVTYPE") == "usb_device" and event.get("ACTION") in ("add", "remove"))


def open_uevent_socket():
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    sock.bind((0, KERNEL_EVENTS_GROUP))
    return sock


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def public(event):
    return {k: v for k, v in event.items() if not k.startswith("_")}


def log_line(record, json_mode):
    if json_mode:
        print(json.dumps(record), flush=True)
        return
    kind = record.get("event")
    if kind == "connected":
        print(f"[{record['status'].upper()}] {record['vendor']} {record['product']} "
              f"({record['id']}) port {record['port']} | interfaces: "
              f"{', '.join(record['interfaces']) or 'none'} | risk: {record['risk']}", flush=True)
        for r in record["reasons"]:
            print(f"    ! {r}", flush=True)
    elif kind == "disconnected":
        print(f"[REMOVED] port {record['port']}", flush=True)
    else:
        print(f"[{kind}] " + ", ".join(f"{k}={v}" for k, v in record.items() if k != "event"), flush=True)


def handle_event(uevent, args, sessions_fn=find_sessions, notify=send_notifications, sysfs=SYSFS):
    if uevent["ACTION"] == "remove":
        record = {"event": "disconnected", "port": os.path.basename(uevent.get("DEVPATH", "")),
                  "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        log_line(record, args.json)
        return record
    device = read_device(uevent["DEVPATH"], sysfs)
    device["status"] = wait_for_decision(device["_base"], args.timeout)
    record = {"event": "connected", "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **public(device)}
    log_line(record, args.json)
    if not args.no_notify:
        notify(record, sessions_fn(only=args.user))
    return record


def list_devices(sysfs=SYSFS):
    """Audit every USB device currently connected."""
    root = os.path.join(sysfs, "bus/usb/devices")
    devices = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return devices
    for name in names:
        if ":" in name:  # interface entries, not devices
            continue
        real = os.path.realpath(os.path.join(root, name))
        devpath = "/" + os.path.relpath(real, sysfs)
        device = read_device(devpath, sysfs)
        state = read_authorized(device["_base"])
        device["status"] = "allowed" if state else "blocked"
        devices.append(public(device))
    return devices


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="usb-snitch",
        description="Real-time USB device alerts with BadUSB heuristics, for USBGuard users.",
    )
    p.add_argument("--list", action="store_true", help="audit currently connected devices and exit")
    p.add_argument("--json", action="store_true", help="output JSON lines")
    p.add_argument("--no-notify", action="store_true", help="log only; don't show desktop notifications")
    p.add_argument("--user", action="append", metavar="NAME",
                   help="only notify this user (repeatable; default: every logged-in desktop user)")
    p.add_argument("--timeout", type=float, default=2.0, metavar="SECONDS",
                   help="how long to wait for an authorization decision (default: 2)")
    p.add_argument("--test-notification", action="store_true",
                   help="send a sample alert to check notifications, then exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list:
        devices = list_devices()
        if args.json:
            for d in devices:
                print(json.dumps(d))
        elif not devices:
            print("No USB devices found.")
        else:
            for d in devices:
                log_line({"event": "connected", **d}, json_mode=False)
        return 0

    if args.test_notification:
        sample = {"status": "blocked", "product": "Test Device", "vendor": "USBSnitch", "id": "0000:0000",
                  "port": "test", "interfaces": ["Keyboard", "Mass Storage"], "risk": "high",
                  "reasons": ["this is a test notification"]}
        sessions = find_sessions(only=args.user)
        if not sessions:
            print("No desktop session bus found under /run/user.", file=sys.stderr)
            return 1
        send_notifications(sample, sessions)
        print("Sent to: " + ", ".join(s[2] for s in sessions))
        return 0

    if os.geteuid() != 0 and not args.no_notify:
        print("[-] Not running as root: notifications will only reach your own session.", file=sys.stderr)

    try:
        sock = open_uevent_socket()
    except OSError as e:
        print(f"[-] Cannot subscribe to kernel USB events: {e}", file=sys.stderr)
        return 1

    if not args.json:
        print(f"[*] USBSnitch {__version__} is monitoring USB events", flush=True)
    try:
        while True:
            ready, _, _ = select.select([sock], [], [])
            if not ready:
                continue
            event = parse_uevent(sock.recv(65536))
            if is_usb_device_event(event):
                handle_event(event, args)
    except KeyboardInterrupt:
        if not args.json:
            print("\n[*] Stopping USBSnitch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
