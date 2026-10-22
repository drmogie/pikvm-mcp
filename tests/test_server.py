"""Tests with a fake PiKVM web server and a fake SSH layer. Run: python tests/test_server.py"""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pikvm_mcp import server as s  # noqa: E402

SEEN = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _go(self, method):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        SEEN.append((method, u.path, parse_qs(u.query), body, dict(self.headers)))
        sent = self.headers.get("X-KVMD-Passwd") or ""
        good = ("pw" + self.server.tag)
        ok = (sent[:len(good)] == good and len(sent) == len(good) + 6 and sent[len(good):].isdigit()) if getattr(self.server, "expect_totp", False) else sent == good
        if not ok:
            self.send_response(401); self.end_headers(); self.wfile.write(b'{"ok":false,"result":{"error":"ForbiddenError"}}'); return
        if u.path == "/api/streamer/snapshot" and getattr(self.server, "snap503", 0) > 0:
            self.server.snap503 -= 1
            self.send_response(503); self.end_headers(); self.wfile.write(b'{"ok":false,"result":{"error":"UnavailableError"}}'); return
        if u.path == "/api/streamer/snapshot":
            self.send_response(200); self.send_header("Content-Type", "image/jpeg"); self.end_headers(); self.wfile.write(b"\xff\xd8JPEG"); return
        if u.path == "/api/streamer/ocr":
            self.send_response(200); self.end_headers(); self.wfile.write(b"login: "); return
        if u.path == "/api/log":
            self.send_response(200); self.end_headers(); self.wfile.write(b"\n".join(b"line%d" % i for i in range(500))); return
        if u.path == "/api/msd/remove":
            self.send_response(400); self.end_headers(); self.wfile.write(b'{"ok":false,"result":{"error":"MsdError","error_msg":"no such image"}}'); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "result": {"path": u.path, "tag": self.server.tag}}).encode())

    do_GET = lambda self: self._go("GET")
    do_POST = lambda self: self._go("POST")
    do_DELETE = lambda self: self._go("DELETE")


def serve(tag):
    srv = HTTPServer(("127.0.0.1", 0), H); srv.tag = tag
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


fails = 0
def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


# ---- tiers
check("api GET read", s.classify_api("GET", "/api/atx", {}) == "read")
check("atx on = change", s.classify_api("POST", "/api/atx/power", {"action": "on"}) == "change")
check("atx off_hard = destructive", s.classify_api("POST", "/api/atx/power", {"action": "off_hard"}) == "destructive")
check("atx click = destructive", s.classify_api("POST", "/api/atx/click", {"button": "reset"}) == "destructive")
check("msd remove destructive", s.classify_api("POST", "/api/msd/remove", {}) == "destructive")
check("hid print = change", s.classify_api("POST", "/api/hid/print", {}) == "change")
for cmd, want in [
    ("uptime", "read"), ("df -h", "read"), ("cat /etc/kvmd/override.yaml", "read"),
    ("systemctl status kvmd", "read"), ("journalctl -u kvmd -n 50 | tail -20", "read"),
    ("kvmd -m", "read"), ("pacman -Q | grep kvmd", "read"), ("vcgencmd measure_temp", "read"),
    ("ip -br a", "read"), ("ls /etc/kvmd", "read"),
    ("cat /etc/kvmd/htpasswd", "blocked"), ("cat /etc/shadow", "blocked"),
    ("cat /etc/kvmd/override.yaml; rm -rf /", "destructive"),
    ("cat /etc/kvmd/../shadow", "blocked"), ("cat /etc/fstab", "read"),
    ("reboot", "destructive"), ("rm -rf /var", "destructive"), ("pacman -Syu", "destructive"),
    ("pikvm-update", "destructive"), ("systemctl stop kvmd", "destructive"),
    ("systemctl restart kvmd-vnc", "change"), ("date -s 2020-01-01", "destructive"),
    ("mount -o remount,rw /", "destructive"), ("echo hi > /tmp/x", "change"),
    ("dmesg -c", "change"), ("ip addr add 1.2.3.4/24 dev eth0", "change"),
    ("uptime | sed s/a/b/", "destructive"), ("", "blocked"),
]:
    got = s.classify_ssh(cmd)
    check(f"ssh {cmd!r} -> {want}" + ("" if got == want else f" (got {got})"), got == want)
check("service status read", s.classify_service("status", "kvmd") == "read")
check("service restart kvmd destructive", s.classify_service("restart", "kvmd.service") == "destructive")
check("service restart vnc change", s.classify_service("restart", "kvmd-vnc") == "change")
check("service stop destructive", s.classify_service("stop", "kvmd-vnc") == "destructive")
check("config path ok", s.config_path_ok("/etc/kvmd/override.yaml") == "")
check("config path secret", s.config_path_ok("/etc/kvmd/htpasswd") != "")
check("config path escape", s.config_path_ok("/etc/kvmd/../shadow") != "")
check("config path other", s.config_path_ok("/etc/fstab") != "")

# ---- more read-only commands (2026.10.22.03)
for cmd, want in [
    ("cat /etc/fstab", "read"), ("cat /etc/fstab | grep OSISO", "read"),
    ("find /etc/kvmd -newer /etc/hostname -type f", "read"), ("find /etc -name x -exec cat {} +", "change"),
    ("find /tmp -delete", "change"), ("find / -exec rm {} ;", "destructive"),
    ("pgrep -a pacman", "read"), ("pgrep -a pacman | tail -3", "read"),
    ("ps aux | grep pacman", "read"), ("findmnt -T /var/lib/pacman", "read"),
    ("du -sh /var/lib/kvmd/msd", "read"), ("stat /etc/fstab", "read"),
    ("showmount -e 172.16.10.11", "read"), ("mountpoint -q /var/lib/kvmd/msd/NFS_Primary", "read"),
    ("runuser -u kvmd -- ls /var/lib/kvmd/msd/NFS_Primary", "read"),
    ("runuser -u kvmd ls /tmp", "read"), ("runuser -u root -- ls /tmp", "change"),
    ("runuser -u kvmd -- rm /tmp/x", "destructive"), ("runuser -u kvmd -- sh -c id", "destructive"),
    ("runuser -u kvmd -- touch /tmp/x", "change"), ("runuser -u kvmd -- cat /etc/kvmd/htpasswd", "blocked"),
    ("runuser -u kvmd -- runuser -u root -- ls", "change"), ("runuser", "change"),
    ("stat /etc/kvmd/htpasswd", "blocked"),
]:
    got = s.classify_ssh(cmd)
    check(f"more read {cmd!r} -> {want}" + ("" if got == want else f" (got {got})"), got == want)
check("fstab not allowed for config tools", s.config_path_ok("/etc/fstab") != "")

# ---- pipelines and 2FA
for cmd, want in [
    ('journalctl -u kvmd -n 40 --no-pager | grep -iE "auth|forbid" | tail -15', "read"),
    ("uptime; reboot", "destructive"), ("uptime | tail && reboot", "destructive"),
    ("uptime || reboot", "destructive"), ("cat /etc/kvmd/override.yaml > /tmp/x", "change"),
    ('grep "a`reboot`" /etc/kvmd/override.yaml', "destructive"), ("uptime | (reboot)", "destructive"),
    ("kvmd -m | grep -A10 auth:", "read"), ('ls "/etc/kvmd"', "read"),
]:
    got = s.classify_ssh(cmd)
    check(f"pipeline {cmd!r} -> {want}" + ("" if got == want else f" (got {got})"), got == want)
check("totp matches RFC 6238 test vector", s._totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now=59) == "287082")
check("totp spaces and lowercase ok", s._totp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", now=59) == "287082")

# ---- single server
a, ua = serve("A")
os.environ.update(PIKVM_URL=ua, PIKVM_PASSWORD="pwA")
for k in ("PIKVM_SERVERS",):
    os.environ.pop(k, None)
r = s.pikvm_info()
check("info works, header auth sent", '"/api/info"' in r and {k.lower(): v for k, v in SEEN[-1][4].items()}.get("x-kvmd-passwd") == "pwA" and {k.lower(): v for k, v in SEEN[-1][4].items()}.get("x-kvmd-user") == "admin")
check("info fields sent", SEEN[-1][2].get("fields") == ["system,hw,meta"])
check("status joins four calls", all(k in s.pikvm_status() for k in ("atx", "streamer", "hid", "msd")))
r = s.pikvm_power("off_hard")
check("power off gated", r.startswith("NOT RUN") and "confirm_phrase" in r)
n = len(SEEN)
r = s.pikvm_power("off_hard", confirm=True)
check("power off needs phrase", r.startswith("NOT RUN") and len(SEEN) == n)
r = s.pikvm_power("off_hard", confirm=True, confirm_phrase="/api/atx/power")
check("power off runs with phrase", '"/api/atx/power"' in r and SEEN[-1][2]["action"] == ["off_hard"] and SEEN[-1][2]["wait"] == ["1"])
check("power on only needs confirm", s.pikvm_power("on").startswith("NOT RUN") and "/api/atx/power" in s.pikvm_power("on", confirm=True))
check("power status runs", "/api/atx" in s.pikvm_power("status"))
r = s.pikvm_call("GET", "/api/auth/check")
check("auth path blocked", r.startswith("ERROR"))
r = s.pikvm_call("GET", "/etc/passwd")
check("non-api path blocked", r.startswith("ERROR"))
s.pikvm_call("GET", "/api/log", {"follow": True})
check("log follow forced off", SEEN[-1][2]["follow"] == ["0"])
check("log tail", s.pikvm_log(lines=3).splitlines() == ["line497", "line498", "line499"])
r = s.pikvm_type(text="hello")
check("type gated", r.startswith("NOT RUN"))
s.pikvm_type(text="héllo", confirm=True)
check("type sends body + limit", SEEN[-1][1] == "/api/hid/print" and SEEN[-1][3] == "héllo".encode() and SEEN[-1][2]["limit"] == ["0"])
s.pikvm_type(shortcut="ControlLeft,AltLeft,Delete", confirm=True)
check("shortcut sent", SEEN[-1][2]["keys"] == ["ControlLeft,AltLeft,Delete"])
check("type needs one input", s.pikvm_type().startswith("ERROR") and s.pikvm_type(text="a", shortcut="b").startswith("ERROR"))
r = s.pikvm_msd("remove", image="x.iso", confirm=True, confirm_phrase="/api/msd/remove")
check("kvmd error is readable", "no such image" in r and r.startswith("ERROR"))
s.pikvm_msd("select", image="a.iso", confirm=True)
check("msd select params", SEEN[-1][2]["image"] == ["a.iso"] and SEEN[-1][2]["cdrom"] == ["1"] and SEEN[-1][2]["rw"] == ["0"])
img = s.pikvm_snapshot()
check("snapshot returns image", getattr(img, "data", b"").startswith(b"\xff\xd8"))
check("snapshot ocr", "login" in s.pikvm_snapshot(ocr=True))
s.STREAMER_RETRY_WAITS = (0, 0, 0)
a.snap503 = 2
check("snapshot retries after 503", getattr(s.pikvm_snapshot(), "data", b"").startswith(b"\xff\xd8"))
n = len(SEEN); a.snap503 = 9
r = s.pikvm_snapshot()
check("snapshot gives idle hint after 3 tries", isinstance(r, str) and "not running" in r and "web page" in r and len(SEEN) - n == 3)
a.snap503 = 0
bad = os.environ["PIKVM_PASSWORD"]; os.environ["PIKVM_PASSWORD"] = "s3cretpw"
r = s.pikvm_info(); check("401 hint, no password leak", "HTTP 401" in r and "s3cretpw" not in r)
os.environ["PIKVM_PASSWORD"] = bad
check("endpoints search", "send_shortcut" in s.pikvm_endpoints("shortcut"))
check("servers hides passwords", "pwA" not in s.pikvm_servers())

# ---- several servers
b, ub = serve("B")
os.environ.pop("PIKVM_URL"); os.environ.pop("PIKVM_PASSWORD")
os.environ.update(PIKVM_SERVERS="pi-kvm01,thewall-pikvm", PIKVM_URL_PI_KVM01=ua, PIKVM_PASSWORD_PI_KVM01="pwA",
                  PIKVM_URL_THEWALL_PIKVM=ub, PIKVM_PASSWORD_THEWALL_PIKVM="pwB")
check("needs server name", s.pikvm_info().startswith("ERROR") and "pi-kvm01" in s.pikvm_info())
check("unknown server", s.pikvm_info(server="nope").startswith("ERROR"))
r = s.pikvm_info(server="all")
check("all reads both", '"tag": "A"' in r and '"tag": "B"' in r)
check("change on all refused", s.pikvm_power("on", confirm=True, server="all").startswith("ERROR"))
check("thewall works", '"tag": "B"' in s.pikvm_info(server="THEWALL-pikvm"))
os.environ.pop("PIKVM_PASSWORD", None)
os.environ["PIKVM_PASSWORD_PI_KVM01"] = ""
check("missing group password is an error, not a fallback", s.pikvm_info(server="pi-kvm01").startswith("ERROR"))
os.environ["PIKVM_PASSWORD_PI_KVM01"] = "pwA"

# ---- 2FA end to end
c2, uc = serve("C")
c2.expect_totp = True
os.environ.update(PIKVM_SERVERS="tfa", PIKVM_URL_TFA=uc, PIKVM_PASSWORD_TFA="pwC")
os.environ.pop("PIKVM_TOTP_SECRET_TFA", None)
r = s.pikvm_info(server="tfa")
check("no secret: login refused, hint mentions 2FA", "HTTP 403" in r or "HTTP 401" in r)
check("hint mentions PIKVM_TOTP_SECRET", "PIKVM_TOTP_SECRET" in r)
os.environ["PIKVM_TOTP_SECRET_TFA"] = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
r = s.pikvm_info(server="tfa")
sent = {k.lower(): v for k, v in SEEN[-1][4].items()}["x-kvmd-passwd"]
check("password plus 6 digit code sent", sent.startswith("pwC") and len(sent) == 9 and sent[3:].isdigit())
os.environ.pop("PIKVM_TOTP_SECRET_TFA"); os.environ.update(PIKVM_SERVERS="pi-kvm01,thewall-pikvm")

# ---- ssh layer (faked)
calls = []
def fake_exec(server, command, timeout=60):
    calls.append((server, command))
    return {"ok": True, "out": "up 3 days\n", "err": "", "code": 0}
s._ssh_exec = fake_exec
files = {"/etc/kvmd/override.yaml": "kvmd:\n    hid:\n        mouse:\n            absolute: true\n"}
writes = []
s._ssh_read_file = lambda server, path: {"ok": True, "text": files.get(path)}
def fake_write(server, path, text, validate):
    writes.append((server, path, text, validate)); return {"ok": True, "backup": path + ".bak-1", "note": "Check passed (kvmd -m)."}
s._ssh_write_file = fake_write

check("ssh read runs", "up 3 days" in s.pikvm_ssh("uptime", server="pi-kvm01") and calls[-1] == ("pi-kvm01", "uptime"))
n = len(calls)
check("ssh change gated", s.pikvm_ssh("echo a > /tmp/x", server="pi-kvm01").startswith("NOT RUN") and len(calls) == n)
check("ssh destructive needs phrase", s.pikvm_ssh("reboot", confirm=True, server="pi-kvm01").startswith("NOT RUN") and len(calls) == n)
check("ssh destructive runs", "up 3 days" in s.pikvm_ssh("reboot", confirm=True, confirm_phrase="reboot", server="pi-kvm01"))
check("ssh secret blocked", s.pikvm_ssh("cat /etc/kvmd/htpasswd", server="pi-kvm01").startswith("ERROR"))
check("ssh all for reads", s.pikvm_ssh("uptime", server="all").count("===") == 4)
check("ssh all for change refused", s.pikvm_ssh("echo a > /x", confirm=True, server="all").startswith("ERROR"))
check("system info", "up 3 days" in s.pikvm_system_info(server="pi-kvm01") and "vcgencmd" in calls[-1][1])
check("config read", "absolute" in s.pikvm_config_read(server="pi-kvm01"))
check("config read secret blocked", s.pikvm_config_read("/etc/kvmd/htpasswd", server="pi-kvm01").startswith("ERROR"))
check("config read missing file", "does not exist" in s.pikvm_config_read("/etc/kvmd/web.css", server="pi-kvm01"))
new = files["/etc/kvmd/override.yaml"] + "    jiggler: true\n"
r = s.pikvm_config_write("/etc/kvmd/override.yaml", new, server="pi-kvm01")
check("config write shows diff, no write", r.startswith("NOT RUN") and "+    jiggler: true" in r and not writes)
r = s.pikvm_config_write("/etc/kvmd/override.yaml", new, confirm=True, server="pi-kvm01")
check("config write runs with validation", "Wrote" in r and writes[-1][3] == "kvmd -m >/dev/null" and "Backup" in r and "Not restarted" in r)
r = s.pikvm_config_write("/etc/kvmd/override.yaml", new, restart="kvmd", confirm=True, server="pi-kvm01")
check("restart kvmd needs phrase", r.startswith("NOT RUN") and "confirm_phrase=\"kvmd\"" in r)
nw = len(writes)
r = s.pikvm_config_write("/etc/kvmd/override.yaml", new, restart="kvmd", confirm=True, confirm_phrase="kvmd", server="pi-kvm01")
check("restart kvmd runs", len(writes) == nw + 1 and calls[-1][1] == "systemctl restart kvmd" and "done" in r)
check("write same content is a no-op", "Nothing to do" in s.pikvm_config_write("/etc/kvmd/override.yaml", files["/etc/kvmd/override.yaml"], server="pi-kvm01"))
check("write to secret refused", s.pikvm_config_write("/etc/kvmd/htpasswd", "a", server="pi-kvm01").startswith("ERROR"))
check("write secret content refused", s.pikvm_config_write("/etc/kvmd/web.css", "password: hunter2\n", server="pi-kvm01").startswith("ERROR"))
check("write needs one server", s.pikvm_config_write("/etc/kvmd/web.css", "a{}", server="all").startswith("ERROR"))
check("service status runs", s.pikvm_service("status", "kvmd", server="pi-kvm01").startswith("up") and "status --no-pager" in calls[-1][1])
check("service restart vnc gated", s.pikvm_service("restart", "kvmd-vnc", server="pi-kvm01").startswith("NOT RUN"))
check("service bad unit", s.pikvm_service("status", "kvmd; reboot", server="pi-kvm01").startswith("ERROR"))
check("service stop needs phrase", "confirm_phrase" in s.pikvm_service("stop", "kvmd-vnc", confirm=True, server="pi-kvm01"))
check("ssh settings: host from url, root", s._ssh_settings("pi-kvm01")["host"] == "127.0.0.1" and s._ssh_settings("pi-kvm01")["user"] == "root")
print("\nFAILED: %d" % fails if fails else "\nALL PASSED")
sys.exit(1 if fails else 0)
