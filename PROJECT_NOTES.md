# PiKVM MCP - project notes

## 2026-10-22: first build (2026.10.22.01)

- Ask: "an MCP for pikvms that helps setup or configure settings, app side and server side."
- Mogie chose: web API plus SSH, all four PiKVMs in one multi-server entry, confirm step plus a phrase for risky.
- PiKVMs: pi-kvm01 172.16.10.29, thewall-pikvm 172.16.10.80, thevm01-pikvm 172.16.10.81, thevm02-pikvm 172.16.10.82. Same address list as in Termix.
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
- Web API said 403 Forbidden. First guess was 2FA because /etc/kvmd/totp.secret exists, but that was WRONG (2FA was off; the file is empty). Real cause: the web user was renamed, so the default `admin` failed. Fix: PIKVM_USER(_<NAME>). PiKVM sends 403 here, not 401.
- Fix: PIKVM_TOTP_SECRET(_<NAME>) makes the 6 digit code in the tool (stdlib HMAC, tested against the RFC 6238 vector). The tool still never reads totp.secret; Mogie pastes it into the desktop config himself.
- Bug found by the live test: the read-level check split pipelines on every `|`, even inside quotes, so `grep -iE "a|b"` was treated as a change. Now uses shlex with punctuation tokens.
- Tightened the risky-command regex to catch `(reboot)`, `;reboot`, and backticks.
- pi-kvm01 has two addresses: eth0 172.16.10.113 and wlan0 172.16.10.29 (the one in the config).
- Lesson: unit tests with a fake server do not catch real-device auth rules (2FA). Test the real device early.

## 2026-10-22: live changes on the PiKVMs (config only, no code change)

Settings were changed on the devices through the tool. Nothing here needed a new release.

pi-kvm01 (test box, done first):
- Enabled VNC (kvmd-vnc, port 5900).
- Enabled local keyboard and mouse (kvmd-localhid, needs KVMD 4.74+). Hotkeys: LeftAlt, LeftAlt, K (local) and LeftAlt, LeftAlt, H (host).
- Enabled USB network (kvmd-otgnet) with `otg.devices.ethernet` driver rndis. PiKVM is 172.30.30.1 on usb0. Target can only ping and use DHCP. Needs a reboot.
- NFS ISO share in /etc/fstab: `172.16.10.11:/volume3/OSISO  /var/lib/kvmd/msd/NFS_Primary  nfs vers=3,timeo=1,retrans=1,soft,nolock  0 0`.
- Backups left on the box: override.yaml.bak-20261022140704 and /etc/fstab.bak-20261022 (plus -2, -3, -4).

thewall-pikvm, thevm01-pikvm, thevm02-pikvm (Linux targets):
- Their override.yaml was stock. Nothing extra to merge.
- Enabled VNC and local keyboard and mouse. NFS added. All rebooted.
- USB network was added, then undone the same day at Mogie's request (override restored from backup, kvmd-otgnet disabled). It never went live.
- Mogie updated all four with pikvm-update (kvmd 4.197 to 4.227) before the NFS step.

NFS lessons (these cost a lot of time):
- Needs the `nfs-utils` package. The three fresh boxes did not have it. Symptom: "mount program didn't pass remote address".
- A stale /var/lib/pacman/db.lck (empty file, mode 000, from an old update) blocked pacman with "unable to lock database", even in rw mode. Check `pgrep -a pacman`, then delete the file.
- Test a share first by mounting it in /tmp and listing as the kvmd user: `runuser -u kvmd -- ls`. If root can read it and kvmd cannot, kvmd will fail.
- kvmd (uid 970) got "Permission denied" because the Synology folder showed mode 000 over NFS (ACL-managed shared folder). Fix on the NAS: `chmod 777 /volume3/OSISO`, with NFS rules set to No mapping.
- kvmd's inotify watcher shows a misleading "Errno 0" when the real cause is permission denied.
- Restarting kvmd with a new NFS mount can take the virtual drive offline. Reboot instead, as the PiKVM docs say. Keep the fstab line commented out until the kvmd user test passes.
- Mount folders under /var/lib/kvmd/msd need `kvmd-helper-otgmsd-remount rw` before mkdir (and `ro` after).
- Reboot takes several minutes. Web and SSH refuse connections, then 502 from nginx, then it works.
- Synology rules for the PiKVMs are now Read only. Uploading to the NFS folder from the PiKVM page will fail. Put ISOs on the NAS directly.
- ISO attach test passed: pi-kvm01 (PiKVM side only) and thevm01-pikvm (the Linux box showed a new 5.8 MB CD-ROM, `sr0`). Detached afterward.
- Screenshot got HTTP 503 on thevm01-pikvm even though video was fine (1280x720p60). The kvmd streamer only runs while a viewer is connected (web page or VNC). It started when VNC connected, and then the snapshot worked. Earlier I guessed a retry would wake it. That is NOT proven; only opening a viewer is.
- Not tested on real targets: USB network link, local keyboard and mouse.

Tool gaps found (ideas for the next release, ask Mogie first):
- Add /etc/fstab to the read allowlist (`cat /etc/fstab` was gated as a change). DONE in 2026.10.22.03. It is read-only for `cat`; the config tools still refuse it.
- Harmless read-only commands (`find`, `pgrep`, `findmnt`, `runuser ... ls`) are gated as changes or destructive. DONE in 2026.10.22.03 (plus `cat /etc/fstab`, `ps`, `du`, `stat`, `mountpoint`, `showmount`, `nfsstat`). Still gated on purpose: `find` with `-exec` or `-delete`, `runuser` as root, `mkdir`, `touch`, `mount`.
- The confirm phrase asked for is the first word of the command, and it differs from what the message says at times. Read the NOT RUN message.
- Clearer NFS error text when the kvmd user cannot read the mount.
- pikvm_service takes one `unit` at a time, and its enable fails on the read-only disk. Make it do rw and ro itself.
- Sleep or wait in the cloud shell is blocked, and the cloud container cannot reach the LAN. All PiKVM calls go through the PC.
- The Claude desktop config lives in AppData, outside the connected folders, so Claude cannot edit it. Mogie edits it by hand.

## 2026-10-22: release 2026.10.22.03 (not pushed yet at time of writing)

- Screenshot retry: 3 tries (0, 2, 3 second waits) on HTTP 503, then a clear "open the web page or VNC" message. Applies to snapshot, the full size save and OCR. Tests set `STREAMER_RETRY_WAITS` to zeros.
- Wider read-only allowlist (see the changelog). `FIND_BAD` lists the find options that are never a read. `CAT_READ_ONLY_FILES` holds files that `cat` may show but the config tools must not touch.
- Tests: 136 checks in tests/test_server.py plus tests/test_ssh_write.py, all pass. Run them with a venv that has `mcp` and `paramiko`, using `python -I`.
- Next ideas: pikvm_service doing rw and ro itself and accepting several units; a short wait or "reboot and wait" helper.

## 2026-10-22 (evening): pi-kvm01 shares its network with the connected PC

Config on the device only. No code change, no release.

- Ask: "set it where the NIC is used to provide network to the connected PC." Mogie then said: eth0 goes to a PC that is being serviced, Wi-Fi is how pi-kvm01 gets internet, and USB networking may or may not work (a test for when a PC is on).
- Uplink: wlan0 (172.16.10.29). eth0 had no cable and is now the port for the PC, so pi-kvm01 is no longer reachable by cable on the LAN. Wi-Fi is the only way in.
- eth0: /etc/systemd/network/eth0.network now has static 172.31.31.1/24, `DHCPServer=yes` (pool 172.31.31.10 to 109, DNS 1.1.1.1 and 1.0.0.1) and `IPMasquerade=ipv4`. This is systemd-networkd's own DHCP server and NAT. No dnsmasq needed. The old file is kept as eth0.network.bak-20261022 (networkd ignores it).
- Applied with `networkctl reload` then `networkctl reconfigure eth0`. wlan0 stayed up. With no cable, eth0 sits at "no-carrier (configuring)" and the address and NAT rules appear when a cable is plugged in.
- networkd logged: IPMasquerade turns on global IPv6 forwarding, which can affect IPv6 router adverts on wlan0. IPv4 is not affected. Not chased.
- USB network (rndis) kept on as a second path. It uses 172.30.30.0/24 with `otgnet.firewall.forward_iface: wlan0` and DNS 1.1.1.1 and 1.0.0.1 (`otgnet.commands.post_start_cmd_append: --dhcp-option=6,...`). Docs: https://docs.pikvm.org/usb_ethernet . Restarting only `kvmd-otgnet` applied it (log shows NAT, forwarding and DHCP); the docs say reboot. override.yaml backup: override.yaml.bak-20261022192337.
- Ranges in use: LAN 172.16.x, USB 172.30.30.0/24, eth0 172.31.31.0/24. No overlap.
- usb0 showed DOWN with no host link. The PC side may need its RNDIS adapter enabled. Not tested.
- Open: the PC on eth0 can reach the PiKVM web page and SSH at 172.31.31.1 (passwords still needed). A firewall rule for eth0 can block that if wanted.
- Not tested: a real PC on eth0 (DHCP, NAT, internet). Test when the PC is on.
- Rebooted pi-kvm01 to make it all persistent.
- pi-kvm01 has logged undervoltage in the past (throttle flags past=true). Watch the power supply while it carries traffic.

## 2026-10-22 (night): live test round on pi-kvm01 with the Pi 5 target

All passed. No code change, no release.

- Screenshot works (Pi desktop, 1280x720 at 60 fps).
- Keyboard works. A NumLock press turned the host LED on. It was toggled back after.
- USB network works. The Pi 5 got a lease (172.30.30.22) from pi-kvm01.
- Internet works over USB through pi-kvm01's Wi-Fi: gateway ping, by address, by name, and a ping forced over usb0 (about 20 ms).
- ISO attach already passed on pi-kvm01 and thevm01.
- Still untested: eth0 sharing with a cabled PC, local keyboard and mouse hotkeys on the three Linux boxes, a mouse click test, ISO attach on thewall and thevm02.
- To-do for Mogie: remove the broad star NFS rule on the Synology if it is still there.
