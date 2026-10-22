# PiKVM MCP - project notes

## 2026-10-22: first build (2026.10.22.01)

- Ask: "an MCP for pikvms that helps setup or configure settings, app side and server side."
- Mogie chose: web API plus SSH, all four PiKVMs in one multi-server entry, confirm step plus a phrase for risky.
- PiKVMs: pi-kvm01 172.16.10.29, thewall-pikvm 172.16.10.30, thevm01-pikvm 172.16.10.81, thevm02-pikvm 172.16.10.82. Same address list as in Termix.
- Copied the technitium-mcp layout: env-only secrets, per-server env names, read/change/destructive tiers, `server=all` for reads only.
- Web auth: X-KVMD-User and X-KVMD-Passwd headers on every call. No login call. /api/auth and /api/ws are blocked in pikvm_call.
- API list from the official docs (docs.pikvm.org/api). Built in as `ENDPOINTS`; re-check if PiKVM changes the API.
- SSH uses paramiko (works on Windows). Host keys accepted on first use.
- PiKVM root disk is read-only. Config writes run `rw`, copy a backup, write, check with `kvmd -m`, restore on failure, then `ro` in a `finally`.
- Secret files (htpasswd, ipmipasswd, vncpasswd, totp, keys, shadow) are blocked for read, write and shell commands. Passwords go in by hand.
- Unknown shell commands default to "change". A strict allowlist decides what counts as read.
- `mcp>=1.2,<2` pin kept (mcp 2 renamed FastMCP; see technitium-mcp notes).
- Snapshot tool returns an Image. No return annotation on it because pydantic cannot build a schema for `Image`.
- Lesson repeated: test the real `uvx --from <folder>` launch. A stripped environment makes uvx fail to fetch packages, which looks like "Connection closed". Pass the full environment in the test client.
- Tested: fake PiKVM web server and fake SSH (tests/), plus real stdio launch via uvx (15 tools listed). NOT tested on a real PiKVM or on Windows.
- GitHub repo: NOT created yet. Waiting for Mogie's approval to commit, push and release.

## 2026-10-22: first live test on pi-kvm01 (2026.10.22.02)

- SSH side worked first try (system info, config read, kvmd log path).
- Web API said 403 Forbidden. Cause: pi-kvm01 has /etc/kvmd/totp.secret, so 2FA is on and the plain password is refused. PiKVM sends 403 here, not 401.
- Fix: PIKVM_TOTP_SECRET(_<NAME>) makes the 6 digit code in the tool (stdlib HMAC, tested against the RFC 6238 vector). The tool still never reads totp.secret; Mogie pastes it into the desktop config himself.
- Bug found by the live test: the read-level check split pipelines on every `|`, even inside quotes, so `grep -iE "a|b"` was treated as a change. Now uses shlex with punctuation tokens.
- Tightened the risky-command regex to catch `(reboot)`, `;reboot`, and backticks.
- pi-kvm01 has two addresses: eth0 172.16.10.113 and wlan0 172.16.10.29 (the one in the config).
- Lesson: unit tests with a fake server do not catch real-device auth rules (2FA). Test the real device early.
