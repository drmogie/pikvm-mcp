# PiKVM MCP

An MCP tool that lets Claude look at and configure your PiKVMs.

- **App side:** the PiKVM web API. Power (ATX), screenshots, keyboard, virtual drive (MSD), GPIO, KVM switch, logs.
- **Server side:** SSH as root. Config files, services, health checks.
- **Many PiKVMs in one tool.** Name one, or use `all` for read-only calls.
- **Asks before it changes anything.**

## Safety

Every call has a level.

- **Read.** Runs right away.
- **Change.** Needs `confirm=true`. Claude must ask you first.
- **Risky.** Needs `confirm=true` and a `confirm_phrase`. Power off, reset, deleting images, restarting kvmd, stopping services, reboot, package changes.

Also:

- Passwords come only from environment variables. They are never saved, shown or logged.
- Files with passwords, keys and 2FA secrets are blocked, for reading and writing.
- Config writes make a backup, check the file with `kvmd -m`, and put the old file back if the check fails. The PiKVM disk is set back to read-only afterward.
- In multi-PiKVM mode, each PiKVM only gets its own password.
- The PiKVM certificate is self-signed, so the tool does not check it by default. Set `PIKVM_VERIFY_TLS=true` to check it.
- SSH host keys are accepted the first time. Fine for a home network.

## Tools

App side:

- `pikvm_servers` lists your PiKVMs.
- `pikvm_info` shows version, hardware and health.
- `pikvm_status` shows power, screen, keyboard and mouse, and virtual drive in one go.
- `pikvm_power` controls ATX power.
- `pikvm_snapshot` takes a picture of the target screen. Optional OCR. The PiKVM video stream usually only runs while someone is watching, so if it fails, open the PiKVM web page or VNC first.
- `pikvm_type` types text or a shortcut on the target.
- `pikvm_msd` manages the virtual drive. Select, connect, download an ISO from a URL, remove.
- `pikvm_log` shows the kvmd log.
- `pikvm_endpoints` lists the web API paths.
- `pikvm_call` runs any web API path.

Server side:

- `pikvm_system_info` runs a read-only health check.
- `pikvm_config_read` reads `/etc/kvmd/override.yaml` and other allowed files.
- `pikvm_config_write` replaces a config file. Shows a diff first.
- `pikvm_service` checks, restarts or stops a service.
- `pikvm_ssh` runs any command.

## Install

1. Get the files: `git clone https://github.com/drmogie/pikvm-mcp` (or use `D:\GitHub-Projects\pikvm-mcp`).
2. Add the entry from `claude_desktop_config.example.json` to the Claude desktop MCP config.
3. Fill in the passwords there. **Only in that file. Never in this repo.**
4. Restart Claude.

The default PiKVM web login is `admin`. SSH is `root`. Use your own passwords.

### One PiKVM

```json
"env": {
  "PIKVM_URL": "https://172.16.10.29",
  "PIKVM_PASSWORD": "...",
  "PIKVM_SSH_PASSWORD": "..."
}
```

### Settings

- `PIKVM_URL`, `PIKVM_USER` (default admin), `PIKVM_PASSWORD`
- `PIKVM_SSH_HOST` (default: the host in the URL), `PIKVM_SSH_PORT`, `PIKVM_SSH_USER` (default root)
- `PIKVM_SSH_PASSWORD`, or `PIKVM_SSH_KEY` (path to a private key)
- `PIKVM_VERIFY_TLS`, `PIKVM_DOWNLOAD_DIR`
- Several PiKVMs: `PIKVM_SERVERS`, then `PIKVM_URL_<NAME>`, `PIKVM_PASSWORD_<NAME>`, `PIKVM_SSH_PASSWORD_<NAME>`. `<NAME>` is the name in capitals with other characters turned into `_`.

### 2FA

If 2FA is on for the PiKVM web login (the file `/etc/kvmd/totp.secret` exists), the web API refuses the plain password with a 403 error. Two ways to fix it:

- **Keep 2FA.** Set `PIKVM_TOTP_SECRET_<NAME>` to the secret. The tool makes the 6 digit code itself. To get the secret, SSH in and run `cat /etc/kvmd/totp.secret` yourself. This tool will not show it. Paste it only into the Claude desktop config.
- **Turn 2FA off** for that PiKVM (`kvmd-totp del` over SSH, with the disk set writable). Only do this if you are happy with it.

The PiKVM clock must be right, or the codes will not match.

## Not tested yet on real hardware

Built and tested against a fake PiKVM and a fake SSH layer (`python tests/test_server.py`, `python tests/test_ssh_write.py`). Tested through a real `uvx` launch. Not yet tested on a real PiKVM. Please report what breaks.

Not built: uploading image files from your PC to the virtual drive, the PiKVM Switch firmware tools, and Redfish.

## License

MIT
