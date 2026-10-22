# Changelog

## 2026.10.22.02

- Fix: read-only shell commands with a `|` inside quotes, like `grep "a|b"`, were wrongly treated as changes. Pipes are now read properly.
- Stricter: shell tricks like `(reboot)` or a backtick inside quotes are caught as risky.
- New: 2FA support. Set `PIKVM_TOTP_SECRET` (or `PIKVM_TOTP_SECRET_<NAME>`) and the tool adds the code to the password.
- A 403 from the web API now says to check the web user name (PIKVM_USER) and whether 2FA is on.

## 2026.10.22.01

- First version.
- App side tools: info, status, power, screenshot, type, virtual drive, log, any web API path.
- Server side tools over SSH: health check, read and write config files, services, any command.
- Several PiKVMs in one tool.
- Read, change and risky levels. Config writes keep a backup and are checked with `kvmd -m`.
