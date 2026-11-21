```
'##::::'##::'######::'########:::'######::'##::: ##:'####:'########::'######::'##::::'##:
 ##:::: ##:'##... ##: ##.... ##:'##... ##: ###:: ##:. ##::... ##..::'##... ##: ##:::: ##:
 ##:::: ##: ##:::..:: ##:::: ##: ##:::..:: ####: ##:: ##::::: ##:::: ##:::..:: ##:::: ##:
 ##:::: ##:. ######:: ########::. ######:: ## ## ##:: ##::::: ##:::: ##::::::: #########:
 ##:::: ##::..... ##: ##.... ##::..... ##: ##. ####:: ##::::: ##:::: ##::::::: ##.... ##:
 ##:::: ##:'##::: ##: ##:::: ##:'##::: ##: ##:. ###:: ##::::: ##:::: ##::: ##: ##:::: ##:
. #######::. ######:: ########::. ######:: ##::. ##:'####:::: ##::::. ######:: ##:::: ##:
:.......::::......:::........::::......:::..::::..::....:::::..::::::......:::..:::::..::
```

**Real-time USB device alerts for Linux, with BadUSB detection, built for USBGuard users.**

![Tests](https://github.com/Stlwtrs/USBSnitch/actions/workflows/tests.yml/badge.svg)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of Contents

1. [Why USBSnitch Exists](#why-usbsnitch-exists)
2. [Features](#features)
3. [How It Works](#how-it-works)
4. [BadUSB Detection](#badusb-detection)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Security Design](#security-design)
8. [What Changed in Version 2](#what-changed-in-version-2)
9. [Limitations](#limitations)
10. [Testing](#testing)
11. [Contributing and Security](#contributing-and-security)
12. [How This Was Built](#how-this-was-built)
13. [License and Disclaimer](#license-and-disclaimer)

---

## Why USBSnitch Exists

[USBGuard](https://usbguard.github.io/) blocks unauthorized USB devices, but it works silently. To find out what was just plugged in and whether it was blocked, you have to run `sudo usbguard list-devices` every time.

USBSnitch runs in the background and tells you immediately: what the device is, whether it was allowed or blocked, and whether it looks like an attack tool, such as a "flash drive" that is secretly a keyboard ready to type commands.

---

## Features

- **Instant desktop notifications** for every USB device connected, to every logged-in desktop user, with no configuration
- **Authorization status:** `allowed`, `blocked` or `rejected`, after waiting for USBGuard's decision instead of guessing
- **BadUSB heuristics:** flags keystroke-injection layouts, rogue network adapters, and devices whose name doesn't match what they really are
- **Sees blocked devices too.** It reads the device's raw USB descriptors, which the kernel collects before USBGuard decides, so it can tell you what a blocked device *would* have done
- **Audit mode** (`--list`) for every device currently connected
- **JSON logs** for SIEMs and scripts, plus normal logs in the systemd journal
- **No dependencies:** Python 3.9+ standard library only. `notify-send` (libnotify) shows the notifications
- **Sandboxed systemd service** with a minimal set of capabilities

---

## How It Works

```text
 USB device plugged in
        │
        ▼
 kernel hotplug event ──netlink──► USBSnitch
                                      │
        ┌─────────────────────────────┼──────────────────────────────┐
        ▼                             ▼                              ▼
 read sysfs descriptors      wait for the authorized flag     usb.ids lookup
 (interface classes)         (USBGuard's decision)            (vendor/product names)
        │                             │                              │
        └──────────────► risk assessment + log ◄─────────────────────┘
                                      │
                                      ▼
                notify-send, run as each desktop user (no shell)
```

1. **Listen for kernel events.** USBSnitch subscribes to the kernel's hotplug messages over a netlink socket, the same source `udevadm monitor --kernel` uses, with no extra libraries.
2. **Read what the device is.** From `/sys`, it reads the vendor and product IDs, the device's own name strings, and the `descriptors` file, the raw USB descriptors listing every interface the device offers.
3. **Wait for the decision.** With USBGuard, a new device starts unauthorized and USBGuard then allows it, leaves it blocked, or rejects it (removing it). USBSnitch watches the `authorized` flag for up to 2 seconds (configurable) and reports the outcome.
4. **Assess and report.** It applies the BadUSB heuristics, writes a log line, and sends a notification to each logged-in desktop user.

---

## BadUSB Detection

Attack tools like the USB Rubber Ducky look like flash drives but tell the computer they're keyboards, then type commands faster than a person could react. Network implants such as the LAN Turtle pose as an Ethernet adapter to intercept traffic.

USBSnitch checks the interfaces each device declares:

| Risk | Pattern | Why it matters |
|---|---|---|
| **High** | Keyboard-capable + mass storage | The classic BadUSB layout: a "drive" that can also type |
| **High** | Keyboard-capable + network adapter | Can type commands and redirect traffic |
| **High** | Named like storage ("Flash Drive") but presents only as a keyboard | The device is lying about what it is |
| **Medium** | Network adapter (CDC ECM/NCM/EEM/MBIM, RNDIS) | Can become your default route and capture traffic |
| **Medium** | Keyboard-capable | Expected only if you plugged in a keyboard |
| **Low** | Everything else (storage, mice, audio, webcams...) | |

High-risk devices and blocked devices get a **critical** notification.

**Example log** (from the test suite's simulated devices):

```text
[ALLOWED] SanDisk Cruzer Blade (0781:5567) port 1-2 | interfaces: Mass Storage | risk: low
[BLOCKED] Generic USB Flash Drive (1234:5678) port 1-3 | interfaces: Keyboard, Mass Storage | risk: high
    ! combines a keyboard-capable interface with storage, a common BadUSB layout
[ALLOWED] Linux RNDIS/Ethernet Gadget (0525:a4a2) port 1-4 | interfaces: Network adapter, CDC Data | risk: medium
    ! adds a network adapter, which can redirect or capture traffic
[REMOVED] port 1-2
```

---

## Installation

```bash
git clone https://github.com/Stlwtrs/USBSnitch.git
cd USBSnitch
sudo ./install.sh
sudo systemctl enable --now usb-snitch
```

The installer checks for Python 3.9+, installs `notify-send` if it's missing (pacman, apt or dnf), and sets up the systemd service. No configuration is needed: USBSnitch finds logged-in desktop users automatically.

Check that notifications reach you:

```bash
sudo usb-snitch --test-notification
```

To remove it: `sudo ./uninstall.sh`

---

## Usage

| Command | What it does |
|---|---|
| `sudo systemctl enable --now usb-snitch` | Run in the background, starting at boot |
| `journalctl -u usb-snitch -f` | Follow the alert log |
| `usb-snitch --list` | Audit every USB device connected right now (no root needed) |
| `usb-snitch --list --json` | Same, as JSON lines |
| `sudo usb-snitch` | Run in the foreground |
| `sudo usb-snitch --json` | Foreground, JSON lines for log pipelines |
| `sudo usb-snitch --user alice` | Notify only this user (repeatable) |
| `sudo usb-snitch --no-notify` | Log only |
| `sudo usb-snitch --timeout 5` | Wait up to 5 seconds for USBGuard's decision |

**JSON output**

```json
{"event": "connected", "time": "2026-11-21T08:53:00-0500", "port": "1-3", "id": "1234:5678", "vendor": "Generic", "product": "USB Flash Drive", "interfaces": ["Keyboard", "Mass Storage"], "risk": "high", "reasons": ["combines a keyboard-capable interface with storage, a common BadUSB layout"], "status": "blocked", "...": "..."}
```

---

## Security Design

USBSnitch runs as root and handles text supplied by hardware that may be hostile, so it is built defensively:

- **No shell, anywhere.** `notify-send` runs from an argument list. Device names can't become shell commands, whatever characters they contain.
- **Drops privileges.** Each notification runs as the desktop user who receives it (their UID and GID, with supplementary groups cleared), never as root.
- **Treats device text as hostile.** Name strings are stripped of control characters, length-limited, and markup-escaped so a device can't inject links or formatting into notifications.
- **Read-only.** It only reads sysfs and never writes to the kernel or changes USBGuard's decisions.
- **Sandboxed service.** `ProtectSystem=strict`, `NoNewPrivileges`, network families limited to netlink and Unix sockets, and a capability set of only `CAP_SETUID`, `CAP_SETGID` and `CAP_DAC_READ_SEARCH`.

---

## What Changed in Version 2

Version 1 worked on my machine, but a security review of it found problems that matter more in a tool running as root:

| Version 1 | Problem | Version 2 |
|---|---|---|
| Built the notification as a shell string from device names and ran it with `su -c` | Hostile hardware supplies those names. Safety depended on udev happening to filter quote characters, while SECURITY.md claimed no shell was used | No shell; argument lists only, tested with injection payloads |
| Username and UID hardcoded in the script | Only worked for one user on one machine, after editing the source | Finds every logged-in desktop user automatically |
| "Fingerprinting" checked whether the product name contained "keyboard" | A BadUSB device can call itself anything | Reads the interfaces the device really declares |
| Read the `authorized` flag after a fixed 0.5 s pause | Could report "authorized" before USBGuard decided | Waits for the decision; reports `allowed`, `blocked` or `rejected` |
| Needed `pyudev` | Extra dependency | Standard library only, using netlink directly |
| Service ran as unrestricted root | | Sandboxed with minimal capabilities |
| README described a Bash script using `udevadm` | Didn't match the code | Documentation matches the implementation |

Details are in [CHANGELOG.md](CHANGELOG.md).

---

## Limitations

- **It alerts; it doesn't block.** Blocking is USBGuard's job. Without USBGuard, every device is allowed and USBSnitch is an alert-only monitor.
- **Heuristics, not proof.** A sophisticated device can claim to be only a keyboard and wait for you to plug in a real keyboard. Medium-risk alerts on hardware you just connected are expected.
- **The device's own text is untrusted.** Vendor and product names come from the `usb.ids` database where possible, but USB IDs can be spoofed. Treat names as claims.
- **Root can blind it.** An attacker with root can stop the service or edit its logs. It's a tripwire, not a tamper-proof audit trail.
- **Linux only,** with notifications on desktops that support the freedesktop notification standard (GNOME, KDE, XFCE and most others).

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

27 tests run against a simulated sysfs tree holding real-format USB descriptors, and inject real-format kernel event datagrams into the monitoring loop. They cover descriptor parsing (including truncated and malformed data), every risk rule, the allow/block/reject decision with a simulated USBGuard, string sanitizing, `usb.ids` lookups, session discovery, privilege dropping, and **shell-injection payloads in device names**.

GitHub Actions also runs ShellCheck on the installers and `systemd-analyze verify` on the service file for every push.

---

## Contributing and Security

Bug reports, test results with real hardware, and new detection ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). For security issues, follow [SECURITY.md](SECURITY.md).

---

## How This Was Built

I built version 1 to make my own USBGuard setup easier to live with. Version 2 was redesigned with assistance from Claude (Anthropic's AI assistant) after a security review of version 1. I reviewed the changes and verified them with the test suite and real USB devices on my own system before release.

---

## License and Disclaimer

Released under the [MIT License](LICENSE).

USBSnitch reports on the USB security policy already in place on your system. Use it on machines you own or administer.
