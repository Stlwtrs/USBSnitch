"""Tests for USBSnitch.

USB hardware can't be plugged in during CI, so devices are simulated with a
fake sysfs tree holding real-format USB descriptors, and kernel events are
injected as real-format netlink datagrams.
"""

import argparse
import importlib.util
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("usbsnitch", os.path.join(HERE, "..", "usb-snitch.py"))
us = importlib.util.module_from_spec(spec)
spec.loader.exec_module(us)


# --- Helpers to build real USB descriptors -----------------------------------

def device_desc(vid, pid, dev_class=0):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, dev_class, 0, 0, 64, vid, pid, 0x0100, 1, 2, 3, 1)


def config_desc(n_interfaces):
    return struct.pack("<BBHBBBBB", 9, 2, 9 + 9 * n_interfaces, n_interfaces, 1, 0, 0x80, 50)


def interface_desc(number, cls, sub, proto):
    return struct.pack("<BBBBBBBBB", 9, 4, number, 0, 1, cls, sub, proto, 0)


def descriptors(vid, pid, *interfaces):
    blob = device_desc(vid, pid) + config_desc(len(interfaces))
    for n, (c, s, p) in enumerate(interfaces):
        blob += interface_desc(n, c, s, p)
    return blob


KEYBOARD = (0x03, 0x01, 0x01)
MOUSE = (0x03, 0x01, 0x02)
STORAGE = (0x08, 0x06, 0x50)
RNDIS = (0xE0, 0x01, 0x03)
CDC_ECM = (0x02, 0x06, 0x00)
AUDIO = (0x01, 0x01, 0x00)


class FakeSysfs:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        os.makedirs(os.path.join(self.root, "bus/usb/devices"))

    def add(self, port, vid, pid, interfaces, product=None, manufacturer=None, authorized="1", serial=None):
        devpath = f"/devices/pci0000:00/0000:00:14.0/usb1/{port}"
        base = os.path.join(self.root, devpath.lstrip("/"))
        os.makedirs(base)
        with open(os.path.join(base, "descriptors"), "wb") as f:
            f.write(descriptors(vid, pid, *interfaces))
        files = {"idVendor": f"{vid:04x}", "idProduct": f"{pid:04x}", "authorized": authorized,
                 "product": product, "manufacturer": manufacturer, "serial": serial}
        for name, value in files.items():
            if value is not None:
                with open(os.path.join(base, name), "w") as f:
                    f.write(value + "\n")
        os.symlink(base, os.path.join(self.root, "bus/usb/devices", port))
        os.makedirs(base + f"/{port}:1.0")  # interface dir, must be ignored by --list
        os.symlink(base + f"/{port}:1.0", os.path.join(self.root, "bus/usb/devices", f"{port}:1.0"))
        return devpath, base

    def cleanup(self):
        self.tmp.cleanup()


def args(**kw):
    base = {"json": True, "no_notify": True, "timeout": 0.3, "user": None}
    base.update(kw)
    return argparse.Namespace(**base)


# --- Descriptor parsing ---------------------------------------------------------

class DescriptorTests(unittest.TestCase):
    def test_parses_ids_and_interfaces(self):
        info = us.parse_descriptors(descriptors(0x046D, 0xC31C, KEYBOARD, MOUSE))
        self.assertEqual((info["vendor_id"], info["product_id"]), ("046d", "c31c"))
        self.assertEqual([us.describe_interface(i) for i in info["interfaces"]], ["Keyboard", "Mouse"])

    def test_truncated_blob_does_not_crash(self):
        blob = descriptors(1, 2, KEYBOARD)[:-4]
        self.assertEqual(us.parse_descriptors(blob)["interfaces"], [])

    def test_zero_length_descriptor_stops_parsing(self):
        self.assertEqual(us.parse_descriptors(b"\x00\x04" * 10)["interfaces"], [])

    def test_network_variants_recognised(self):
        for itf in (RNDIS, CDC_ECM, (0x02, 0x0D, 0x00), (0xEF, 0x04, 0x01)):
            self.assertTrue(us.is_network({"class": itf[0], "subclass": itf[1], "protocol": itf[2]}), itf)


# --- Risk heuristics -------------------------------------------------------------

def itfs(*triples):
    return [{"class": c, "subclass": s, "protocol": p} for c, s, p in triples]


class RiskTests(unittest.TestCase):
    def test_flash_drive_is_low(self):
        self.assertEqual(us.assess_risk(itfs(STORAGE), "Cruzer Blade")[0], "low")

    def test_keyboard_plus_storage_is_high(self):
        level, reasons = us.assess_risk(itfs(KEYBOARD, STORAGE), "USB Drive")
        self.assertEqual(level, "high")
        self.assertIn("BadUSB", reasons[0])

    def test_storage_name_but_keyboard_is_high(self):
        level, reasons = us.assess_risk(itfs(KEYBOARD), "SanDisk Flash Drive")
        self.assertEqual(level, "high")
        self.assertIn("presents as a keyboard", reasons[0])

    def test_keyboard_plus_network_is_high(self):
        self.assertEqual(us.assess_risk(itfs(KEYBOARD, RNDIS))[0], "high")

    def test_network_adapter_is_medium(self):
        self.assertEqual(us.assess_risk(itfs(CDC_ECM))[0], "medium")

    def test_plain_keyboard_is_medium(self):
        self.assertEqual(us.assess_risk(itfs(KEYBOARD), "USB Keyboard")[0], "medium")

    def test_mouse_only_is_low(self):
        self.assertEqual(us.assess_risk(itfs(MOUSE))[0], "low")

    def test_audio_is_low(self):
        self.assertEqual(us.assess_risk(itfs(AUDIO))[0], "low")


# --- Sysfs reading and authorization ---------------------------------------------

class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.fs = FakeSysfs()

    def tearDown(self):
        self.fs.cleanup()

    def test_reads_blocked_device_interfaces(self):
        devpath, _ = self.fs.add("1-2", 0x1234, 0x5678, [KEYBOARD, STORAGE],
                                 product="USB Drive", manufacturer="Generic", authorized="0")
        dev = us.read_device(devpath, self.fs.root)
        self.assertEqual(dev["id"], "1234:5678")
        self.assertEqual(dev["interfaces"], ["Keyboard", "Mass Storage"])
        self.assertEqual(dev["risk"], "high")

    def test_device_strings_are_sanitized(self):
        devpath, _ = self.fs.add("1-3", 1, 2, [STORAGE], product="Evil\x1b[2J\x07" + "A" * 200)
        dev = us.read_device(devpath, self.fs.root)
        self.assertNotIn("\x1b", dev["product"])
        self.assertLessEqual(len(dev["product"]), 67)

    def test_allowed_immediately(self):
        _, base = self.fs.add("1-4", 1, 2, [STORAGE], authorized="1")
        self.assertEqual(us.wait_for_decision(base, timeout=0.2), "allowed")

    def test_blocked_after_timeout(self):
        _, base = self.fs.add("1-5", 1, 2, [STORAGE], authorized="0")
        start = time.monotonic()
        self.assertEqual(us.wait_for_decision(base, timeout=0.3, interval=0.05), "blocked")
        self.assertGreaterEqual(time.monotonic() - start, 0.3)

    def test_allowed_after_policy_decision(self):
        _, base = self.fs.add("1-6", 1, 2, [STORAGE], authorized="0")

        def usbguard_allows():
            time.sleep(0.15)
            with open(os.path.join(base, "authorized"), "w") as f:
                f.write("1\n")

        t = threading.Thread(target=usbguard_allows)
        t.start()
        self.assertEqual(us.wait_for_decision(base, timeout=2, interval=0.05), "allowed")
        t.join()

    def test_rejected_device_disappears(self):
        self.assertEqual(us.wait_for_decision(os.path.join(self.fs.root, "gone"), timeout=1), "rejected")

    def test_list_skips_interfaces(self):
        self.fs.add("1-1", 0x046D, 0xC31C, [KEYBOARD])
        self.fs.add("1-2", 0x0781, 0x5567, [STORAGE], authorized="0")
        devices = us.list_devices(self.fs.root)
        self.assertEqual([d["port"] for d in devices], ["1-1", "1-2"])
        self.assertEqual([d["status"] for d in devices], ["allowed", "blocked"])
        for d in devices:
            self.assertNotIn("_base", d)


class UsbIdsTests(unittest.TestCase):
    def test_vendor_and_product_lookup(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("# comment\n046d  Logitech, Inc.\n\tc31c  Keyboard K120\n\tc52b  Unifying Receiver\n"
                    "0781  SanDisk Corp.\n\t5567  Cruzer Blade\nC 00  (Defined at Interface level)\n")
            path = f.name
        try:
            us._usb_ids_cache.clear()
            self.assertEqual(us.lookup_usb_ids("046d", "c31c", (path,)), ("Logitech, Inc.", "Keyboard K120"))
            self.assertEqual(us.lookup_usb_ids("0781", "ffff", (path,)), ("SanDisk Corp.", None))
            self.assertEqual(us.lookup_usb_ids("dead", "beef", (path,)), (None, None))
        finally:
            us._usb_ids_cache.clear()
            os.unlink(path)


# --- Notifications ----------------------------------------------------------------

class NotificationTests(unittest.TestCase):
    EVENT = {"status": "blocked", "product": "'; touch /tmp/pwned; echo '<b>x</b>",
             "vendor": "Evil & Co", "id": "1234:5678", "port": "1-2",
             "interfaces": ["Keyboard", "Mass Storage"], "risk": "high", "reasons": ["test"]}

    def test_no_shell_and_device_text_is_one_argument(self):
        calls = []
        us.send_notifications(self.EVENT, [(1000, 1000, "alice", "/run/user/1000/bus")],
                              run=lambda cmd, **kw: calls.append((cmd, kw)))
        cmd, kw = calls[0]
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], "notify-send")
        self.assertNotIn("shell", kw)
        self.assertNotIn("su", cmd)
        self.assertEqual(len(cmd), 8)  # injection text did not create extra arguments
        self.assertIn("'; touch /tmp/pwned; echo '", cmd[6])
        self.assertIn("&lt;b&gt;", cmd[6])
        self.assertIn("Evil &amp; Co", cmd[7])
        self.assertEqual(kw["env"]["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1000/bus")

    def test_drops_privileges_when_root(self):
        calls = []
        with mock.patch.object(us.os, "geteuid", return_value=0):
            us.send_notifications(self.EVENT, [(1000, 1001, "alice", "/run/user/1000/bus")],
                                  run=lambda cmd, **kw: calls.append(kw))
        self.assertEqual((calls[0]["user"], calls[0]["group"], calls[0]["extra_groups"]), (1000, 1001, []))

    def test_urgency(self):
        ok = dict(self.EVENT, status="allowed", risk="low", reasons=[])
        self.assertEqual(us.notification_for(ok)[2], "normal")
        self.assertEqual(us.notification_for(dict(ok, risk="high", reasons=["x"]))[2], "critical")
        self.assertEqual(us.notification_for(dict(ok, status="blocked"))[2], "critical")

    def test_session_discovery(self):
        with tempfile.TemporaryDirectory() as run_user:
            me = os.geteuid()
            for uid in (str(me), "999999", "notanumber"):
                os.makedirs(os.path.join(run_user, uid))
                open(os.path.join(run_user, uid, "bus"), "w").close()
            os.makedirs(os.path.join(run_user, "4242"))  # no bus socket
            sessions = us.find_sessions(run_user)
        expected = [] if me == 0 else [me]  # root's own session is never notified
        self.assertEqual([s[0] for s in sessions], expected)


# --- Kernel events ------------------------------------------------------------------

def uevent(action, devpath, **props):
    fields = {"ACTION": action, "DEVPATH": devpath, "SUBSYSTEM": "usb", "DEVTYPE": "usb_device", **props}
    return (f"{action}@{devpath}\0" + "\0".join(f"{k}={v}" for k, v in fields.items()) + "\0").encode()


class EventTests(unittest.TestCase):
    def test_parse_and_filter(self):
        ev = us.parse_uevent(uevent("add", "/devices/x/1-2", PRODUCT="1234/5678/100"))
        self.assertEqual(ev["DEVPATH"], "/devices/x/1-2")
        self.assertTrue(us.is_usb_device_event(ev))
        self.assertFalse(us.is_usb_device_event(us.parse_uevent(uevent("add", "/x", DEVTYPE="usb_interface"))))
        self.assertFalse(us.is_usb_device_event(us.parse_uevent(uevent("bind", "/x"))))
        self.assertIsNone(us.parse_uevent(b"libudev\0garbage"))

    def test_handle_add_and_remove(self):
        fs = FakeSysfs()
        try:
            devpath, _ = fs.add("1-2", 0x1234, 0x5678, [KEYBOARD, STORAGE], product="USB Drive", authorized="0")
            notified = []
            buf = io.StringIO()
            with redirect_stdout(buf):
                rec = us.handle_event({"ACTION": "add", "DEVPATH": devpath}, args(no_notify=False),
                                      sessions_fn=lambda only: ["s"], notify=lambda e, s: notified.append(e),
                                      sysfs=fs.root)
                us.handle_event({"ACTION": "remove", "DEVPATH": devpath}, args(), sysfs=fs.root)
            lines = [json.loads(l) for l in buf.getvalue().splitlines()]
            self.assertEqual(rec["status"], "blocked")
            self.assertEqual(lines[0]["risk"], "high")
            self.assertEqual(lines[1], {"event": "disconnected", "port": "1-2", "time": lines[1]["time"]})
            self.assertEqual(len(notified), 1)
        finally:
            fs.cleanup()

    def test_monitor_loop_end_to_end(self):
        """Feed a real-format datagram through main()'s event loop."""
        fs = FakeSysfs()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            devpath, _ = fs.add("3-1", 0x0781, 0x5567, [STORAGE], product="Cruzer Blade")
            b.send(uevent("add", "/devices/x/3-1-interface", DEVTYPE="usb_interface"))  # ignored
            b.send(uevent("add", devpath))
            seen = []
            real_handle = us.handle_event

            def fake_handle(event, a_):
                seen.append(real_handle(event, a_, sysfs=fs.root))
                raise KeyboardInterrupt

            buf = io.StringIO()
            with mock.patch.object(us, "open_uevent_socket", return_value=a), \
                    mock.patch.object(us, "handle_event", side_effect=fake_handle, autospec=False), \
                    redirect_stdout(buf), mock.patch("sys.stderr", io.StringIO()):
                code = us.main(["--json", "--no-notify", "--timeout", "0.2"])
            self.assertEqual(code, 0)
            self.assertEqual(seen[0]["id"], "0781:5567")
            self.assertEqual(seen[0]["status"], "allowed")
        finally:
            a.close()
            b.close()
            fs.cleanup()


if __name__ == "__main__":
    unittest.main()
