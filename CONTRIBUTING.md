# Contributing to USBSnitch

Thanks for your interest in USBSnitch. Bug reports, test results with real hardware, and new detection ideas are all welcome.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Reporting Bugs

Use the **Bug report** form in the Issues tab. Include the output of `usb-snitch --list --json` with the device connected, and the service log (`journalctl -u usb-snitch`). Remove serial numbers first.

## Suggesting Detections

Use the **Feature request** form. Describe the attack or device the rule would catch, and which legitimate hardware it might flag by mistake. False positives train people to ignore alerts.

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Keep USBSnitch dependency-free: Python 3.9+ standard library only.
3. **Never pass device-supplied text through a shell** or into a format that interprets it. Use argument lists for every subprocess.
4. Add tests for new behavior. New detection rules need a test with crafted descriptors in `tests/test_usbsnitch.py`.
5. Make sure everything passes:

   ```bash
   python3 -m unittest discover -s tests -v
   shellcheck -S warning install.sh uninstall.sh
   ```

6. If possible, test with real hardware and describe the devices in the pull request.
7. Update `README.md` and `CHANGELOG.md` if usage or behavior changes.

## Code Style

- Follow PEP 8, with 4-space indentation.
- Explain the *why* behind anything involving USB descriptors, kernel events or privilege handling.
- Keep the service's capabilities minimal. Any new capability needs a comment in `usb-snitch.service` explaining why.
