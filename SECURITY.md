# Security Policy

USBSnitch runs as root and processes text supplied by USB hardware that may be hostile, so security reports are taken seriously and handled privately.

## Supported Versions

| Version | Supported |
|---|:--:|
| 2.x (`main`) | ✅ |
| 1.x | ❌ Builds shell commands from device-supplied names. Please upgrade. |

## Scope

**In scope:**

- Command or code execution through device-supplied data (names, serials, descriptors) or kernel event contents
- Privilege escalation through the service, the installer or notification handling
- Ways a device can avoid being reported, or be reported as something it isn't, beyond the documented limitations
- Weaknesses in the systemd unit's sandboxing

**Out of scope:**

- Attacks by someone who already has root
- Devices that successfully imitate legitimate hardware (a documented limitation of descriptor-based detection)
- Vulnerabilities in USBGuard, the kernel, or the desktop's notification server. Report those upstream.

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and select **Report a vulnerability**. If that isn't possible, email **stlwtrs@proton.me**.

Please include:

- The USBSnitch version (`usb-snitch --version`), distribution and Python version
- Steps to reproduce, and the device or descriptors involved (a hex dump of the sysfs `descriptors` file is ideal)
- The impact: what an attacker gains

## What to Expect

USBSnitch is maintained by one person, so responses are best effort:

- **Acknowledgement** within 7 days
- **A fix or documented mitigation** as soon as practical
- **Credit** in the changelog, unless you prefer to stay anonymous

Please allow reasonable time for a fix before public disclosure.

## Design Principles

- No shell execution; every subprocess uses an argument list
- Notifications run as the receiving user, never as root
- Device-supplied text is treated as hostile: sanitized, length-limited and markup-escaped
- Read-only access to sysfs; USBSnitch never changes authorization decisions
- Minimal service privileges: see `usb-snitch.service`
