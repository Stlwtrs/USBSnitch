# Changelog

All notable changes to USBSnitch are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-21

### Security
- **Removed shell execution.** Notifications were built as a shell command string containing device-supplied names and run with `su -c`. They now run `notify-send` from an argument list, so device names can never be interpreted as commands.
- **Notifications run with the receiving user's privileges** (UID, GID, no supplementary groups) instead of through `su`.
- Device-supplied strings are stripped of control characters, length-limited, and markup-escaped before display.
- The systemd service is sandboxed (`ProtectSystem=strict`, `NoNewPrivileges`, restricted address families, three capabilities).

### Fixed
- **Hardcoded username and UID.** The script only notified one specific user and had to be edited by hand. Logged-in desktop users are now found automatically.
- **Authorization race.** The `authorized` flag was read once after a fixed 0.5 s delay, which could come before USBGuard's decision. USBSnitch now waits for the decision and reports `allowed`, `blocked` or `rejected`.
- **Device type detection** looked for words like "keyboard" in the product name. It now reads the interfaces the device actually declares.
- The README described a Bash script using `udevadm`; it now matches the implementation.
- The service unit hardcoded `DISPLAY` and UID 1000.

### Added
- BadUSB heuristics: keyboard plus storage, keyboard plus network, storage-named keyboards, and network adapters (CDC ECM/NCM/EEM/MBIM and RNDIS)
- Interface detection for blocked devices, from the raw USB descriptors
- Vendor and product names from the `usb.ids` database
- `--list` audit of connected devices, `--json` output, `--user`, `--no-notify`, `--timeout`, `--test-notification` and `--version`
- Disconnect events in the log
- `uninstall.sh`
- Test suite (27 tests) and GitHub Actions CI, including ShellCheck and `systemd-analyze verify`

### Removed
- The `pyudev` dependency. Kernel events are read directly over netlink with the standard library.

## [1.0.0] - 2026-11-10

### Added
- Initial release: `pyudev` monitor that read the `authorized` flag of new USB devices and sent a desktop notification through `notify-send`
