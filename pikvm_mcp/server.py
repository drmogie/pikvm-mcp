"""PiKVM MCP tool.

Lets Claude look at and change one or more PiKVMs.

App side:    the PiKVM web API (power, screen, keyboard, mass storage, GPIO, switch).
Server side: SSH as root (config files, services, system checks).

Settings come from environment variables only. Passwords are never written to
disk, never printed, and never sent anywhere except the PiKVM they belong to.

One PiKVM:
  PIKVM_URL               Example: https://172.16.10.29              (required)
  PIKVM_USER              Web user. Default: admin
  PIKVM_PASSWORD          Web password                                (required)
  PIKVM_VERIFY_TLS        "true" to check the certificate. Default: false (PiKVM is self-signed)
  PIKVM_SSH_HOST          Default: the host in PIKVM_URL
  PIKVM_SSH_PORT          Default: 22
  PIKVM_SSH_USER          Default: root
  PIKVM_SSH_PASSWORD      SSH password (or use a key)
  PIKVM_SSH_KEY           Path to a private key file (optional)
  PIKVM_DOWNLOAD_DIR      Where saved screenshots go

Several PiKVMs in one tool. Set these instead of PIKVM_URL and PIKVM_PASSWORD:
  PIKVM_SERVERS               Names, comma separated: pi-kvm01,thewall-pikvm
  PIKVM_URL_<NAME>            One address per PiKVM. <NAME> is the name in capitals,
                              every other character turned into _
                              (thewall-pikvm becomes PIKVM_URL_THEWALL_PIKVM)
  PIKVM_USER_<NAME>           Optional web user
  PIKVM_PASSWORD_<NAME>       One web password per PiKVM
  PIKVM_SSH_PASSWORD_<NAME>   One SSH password per PiKVM (not needed with a key)
  PIKVM_SSH_HOST_<NAME>, PIKVM_SSH_PORT_<NAME>, PIKVM_SSH_USER_<NAME>,
  PIKVM_VERIFY_TLS_<NAME>     Optional per-PiKVM overrides.
"""

from __future__ import annotations

import difflib
import json
import os
import posixpath
import re
import shlex
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP, Image

__version__ = "2026.10.22.01"

mcp = FastMCP("pikvm")

DEFAULT_SERVER = "default"  # the name used when PIKVM_SERVERS is not set

# ---------------------------------------------------------------------------
# Safety tiers
# ---------------------------------------------------------------------------
# read         runs right away
# change       needs confirm=true (Claude must ask the user first)
# destructive  needs confirm=true AND the confirm_phrase shown in the reply


def classify_api(method: str, path: str, params: dict[str, Any]) -> str:
    method = method.upper()
    p = path.rstrip("/")
    if method == "GET":
        return "read"
    if p in ("/api/atx/power", "/api/switch/atx/power"):
        return "change" if str(params.get("action", "")).lower() == "on" else "destructive"
    if p in ("/api/atx/click", "/api/switch/atx/click"):
        return "destructive"
    if p in ("/api/msd/remove", "/api/msd/reset", "/api/switch/reset",
             "/api/switch/edids/remove"):
        return "destructive"
    return "change"


# Never sent through the generic call. Login is done by the tool itself.
BLOCKED_API_PREFIXES = ("/api/auth", "/api/ws")

# Files that hold secrets. Never shown or written through this tool.
SECRET_RE = re.compile(
    r"(htpasswd|ipmipasswd|vncpasswd|passwd|shadow|totp|secret|id_rsa|id_ed25519|"
    r"authorized_keys|\.key\b|\.pem\b|credentials)", re.I)

SSH_META_RE = re.compile(r"[;&`><]|\$\(|\n|\r")
SSH_FILTERS = {"head", "tail", "grep", "wc", "sort", "uniq", "cut"}
SSH_PLAIN_READ = {"uptime", "df", "free", "uname", "lsblk", "lsusb", "id", "whoami", "ls"}
SSH_DESTRUCTIVE_RE = re.compile(
    r"(^|[\s|])(rm|rmdir|mv|cp|dd|mkfs\S*|fdisk|parted|reboot|poweroff|shutdown|halt|"
    r"passwd|kvmd-htpasswd|kvmd-totp|pikvm-update|pacman|pip|pip3|swapoff|iptables|nft|"
    r"chmod|chown|truncate|tee|umount|kill|killall|pkill|curl|wget|sh|bash|python3?|"
    r"eval|sed|mount|date|hostnamectl|timedatectl|"
    r"systemctl\s+(stop|disable|mask|poweroff|reboot|halt|kexec))(\s|$)")
CAT_OK_PREFIXES = ("/etc/kvmd/", "/proc/", "/sys/class/thermal/")
CAT_OK_FILES = {"/boot/config.txt", "/boot/cmdline.txt", "/etc/os-release", "/etc/hostname"}
SYSTEMCTL_READ = {"status", "is-active", "is-enabled", "is-failed", "list-units",
                  "list-unit-files", "list-timers", "show", "cat"}
VCGENCMD_READ = {"measure_temp", "get_throttled", "measure_volts", "get_config", "version"}


def _argv_is_read(argv: list[str]) -> bool:
    if not argv:
        return False
    prog, args = argv[0], argv[1:]
    if prog in SSH_FILTERS:
        return True
    if prog in SSH_PLAIN_READ:
        return True
    if prog in ("date", "hostname", "mount"):
        return not args
    if prog == "dmesg":
        return not any(a in ("-C", "-c", "--clear", "--console-off", "-D", "-E") for a in args)
    if prog == "journalctl":
        return not any(a.startswith(("--vacuum", "--rotate", "--flush", "--sync")) for a in args)
    if prog == "cat":
        if not args:
            return False
        for a in args:
            clean = posixpath.normpath(a)
            if ".." in a or clean != a.rstrip("/"):
                return False
            if clean not in CAT_OK_FILES and not clean.startswith(CAT_OK_PREFIXES):
                return False
        return True
    if prog == "systemctl":
        sub = [a for a in args if not a.startswith("-")]
        return bool(sub) and sub[0] in SYSTEMCTL_READ
    if prog == "kvmd":
        return args == ["-m"]
    if prog == "pacman":
        return bool(args) and args[0].startswith("-Q")
    if prog == "vcgencmd":
        return bool(args) and args[0] in VCGENCMD_READ
    if prog == "ip":
        sub = [a for a in args if not a.startswith("-")]
        return bool(sub) and sub[0] in {"a", "addr", "address", "route", "link", "neigh"} \
            and not any(w in args for w in ("add", "del", "set", "flush", "replace"))
    if prog == "ss":
        return True
    return False


def classify_ssh(cmd: str) -> str:
    """Returns read, change, destructive or blocked."""
    cmd = cmd.strip()
    if not cmd:
        return "blocked"
    if SECRET_RE.search(cmd):
        return "blocked"
    if not SSH_META_RE.search(cmd):
        segments = [s.strip() for s in cmd.split("|")]
        try:
            argvs = [shlex.split(s) for s in segments]
        except ValueError:
            argvs = []
        if argvs and all(argvs) and _argv_is_read(argvs[0]) \
                and all(a[0] in SSH_FILTERS for a in argvs[1:]):
            return "read"
    if SSH_DESTRUCTIVE_RE.search(cmd):
        return "destructive"
    return "change"


# Services where a restart cuts the web page, the video or the USB link.
CRITICAL_UNITS = {"kvmd", "kvmd-nginx", "kvmd-otg", "kvmd-janus", "sshd", "ssh",
                  "systemd-networkd", "networkmanager", "dhcpcd", "tailscaled"}
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:-]+$")


def classify_service(action: str, unit: str) -> str:
    base = unit.removesuffix(".service").lower()
    if action == "status":
        return "read"
    if action in ("stop", "disable", "mask"):
        return "destructive"
    if base in CRITICAL_UNITS:
        return "destructive"
    return "change"


def config_path_ok(path: str) -> str:
    """Returns an empty string if the path may be used, else the reason."""
    if not path.startswith("/") or ".." in path.split("/"):
        return "Give a full path with no '..'."
    clean = posixpath.normpath(path)
    if SECRET_RE.search(clean):
        return "That file holds secrets. This tool never shows or changes it."
    if clean in CAT_OK_FILES:
        return ""
    if clean.startswith("/etc/kvmd/") and Path(clean).suffix.lower() in {
            ".yaml", ".yml", ".css", ".html", ".js", ".conf", ".jcfg", ".ini", ".txt", ".json"}:
        return ""
    return ("Only /etc/kvmd/ text files (yaml, css, html, conf, jcfg and similar), "
            "/boot/config.txt, /boot/cmdline.txt and /etc/hostname are allowed.")


# ---------------------------------------------------------------------------
# Servers and settings
# ---------------------------------------------------------------------------

def _key(name: str) -> str:
    """thewall-pikvm -> THEWALL_PIKVM"""
    return re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def _server_names() -> list[str]:
    names: list[str] = []
    for n in os.environ.get("PIKVM_SERVERS", "").split(","):
        n = n.strip()
        if n and n.lower() not in [x.lower() for x in names]:
            names.append(n)
    return names


def _setting(server: str, base: str, default: str = "") -> str:
    """A per-server setting, else the global one. Not used for passwords."""
    if server != DEFAULT_SERVER:
        value = os.environ.get(f"{base}_{_key(server)}", "").strip()
        if value:
            return value
    return os.environ.get(base, default).strip() or default


def _secret(server: str, base: str) -> str:
    """A password. In several-server mode it only comes from the per-server
    setting, so one PiKVM's password is never sent to another."""
    if server == DEFAULT_SERVER:
        return os.environ.get(base, "")
    return os.environ.get(f"{base}_{_key(server)}", "")


def _web_config(server: str) -> tuple[str, str, str]:
    if server == DEFAULT_SERVER:
        url = os.environ.get("PIKVM_URL", "").strip().rstrip("/")
        need = "PIKVM_URL and PIKVM_PASSWORD"
    else:
        url = os.environ.get(f"PIKVM_URL_{_key(server)}", "").strip().rstrip("/")
        need = f"PIKVM_URL_{_key(server)} and PIKVM_PASSWORD_{_key(server)}"
    user = _setting(server, "PIKVM_USER", "admin")
    password = _secret(server, "PIKVM_PASSWORD")
    if not url or not password:
        raise RuntimeError(f"Set {need} in this tool's environment (see the README). "
                           "The password is not stored anywhere else.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url, user, password


def _targets(server: str, read_only: bool) -> tuple[list[str], str]:
    """Work out which PiKVM(s) a call goes to. Returns (names, error)."""
    names = _server_names()
    server = (server or "").strip()
    if not names:
        if server and server.lower() != DEFAULT_SERVER:
            return [], "This tool has one PiKVM (PIKVM_SERVERS is not set). Leave server empty."
        return [DEFAULT_SERVER], ""
    listing = ", ".join(names)
    if not server:
        return [], f"This tool has several PiKVMs. Set server to one of: {listing}."
    if server.lower() == "all":
        if not read_only:
            return [], (f"server=all only works for read-only calls. "
                        f"For a change, pick one PiKVM: {listing}.")
        return list(names), ""
    for n in names:
        if n.lower() == server.lower():
            return [n], ""
    return [], f"Unknown PiKVM '{server}'. Use one of: {listing}."


def _scrub(text: str, *secrets: str) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def _to_param(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)


def _download_dir() -> Path:
    base = os.environ.get("PIKVM_DOWNLOAD_DIR")
    path = Path(base) if base else Path.home() / "pikvm-downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Web API
# ---------------------------------------------------------------------------

def _request(method: str, path: str, params: dict[str, Any] | None = None,
             server: str = DEFAULT_SERVER, body: bytes | None = None,
             timeout: int = 30, raw: bool = False) -> dict[str, Any]:
    """Call the PiKVM API. Returns a dict with ok and either data/bytes or error."""
    try:
        base, user, password = _web_config(server)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    query = {k: v for k, v in ((k, _to_param(v)) for k, v in (params or {}).items())
             if v is not None}
    url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
    headers = {"X-KVMD-User": user, "X-KVMD-Passwd": password}
    if body is not None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
    ctx = None
    if url.startswith("https://") and _setting(server, "PIKVM_VERIFY_TLS", "false").lower() != "true":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers, method=method.upper(), data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = resp.read()
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        text = _scrub(exc.read().decode("utf-8", "replace")[:500], password)
        hint = ""
        if exc.code == 401:
            hint = " The web user or password is wrong (or 2FA is on: add the 6 digit code after the password)."
        return {"ok": False, "error": f"HTTP {exc.code} from PiKVM.{hint} {text}".strip()}
    except urllib.error.URLError as exc:
        return {"ok": False, "error": _scrub(f"Could not reach PiKVM: {exc.reason}", password)}
    except TimeoutError:
        return {"ok": False, "error": f"PiKVM did not answer within {timeout} seconds."}
    if raw:
        return {"ok": True, "bytes": payload, "content_type": ctype}
    try:
        doc = json.loads(payload.decode("utf-8"))
    except ValueError:
        return {"ok": True, "data": payload.decode("utf-8", "replace")}
    if isinstance(doc, dict) and doc.get("ok") is False:
        res = doc.get("result", {})
        msg = res.get("error_msg") or res.get("error") or doc
        return {"ok": False, "error": _scrub(f"PiKVM says: {msg}", password)}
    return {"ok": True, "data": doc.get("result", doc) if isinstance(doc, dict) else doc}


def _render(result: dict[str, Any], max_chars: int) -> str:
    if not result.get("ok"):
        return "ERROR: " + result.get("error", "unknown error")
    data = result.get("data")
    text = data if isinstance(data, str) else json.dumps(data, indent=1, ensure_ascii=False)
    if len(text) > max_chars:
        return text[:max_chars] + f"\n... cut at {max_chars} characters. Use max_chars for more."
    return text


def _gate(tier: str, what: str, confirm: bool, phrase: str, need: str,
          server: str, extra: str = "") -> str | None:
    """Return a message if the call must not run yet, else None."""
    if tier == "read":
        return None
    where = "" if server == DEFAULT_SERVER else f"PiKVM: {server}\n"
    if not confirm:
        return (
            f"NOT RUN. This makes a change ({tier}).\n{where}{what}\n{extra}"
            "Tell the user exactly what will change and ask for a clear yes. "
            "Then call again with confirm=true"
            + (f" and confirm_phrase=\"{need}\"." if tier == "destructive" else ".")
        )
    if tier == "destructive" and phrase != need:
        return (
            f"NOT RUN. This can power off or restart the target, cut access, or delete data.\n"
            f"{where}{what}\n{extra}"
            f"Ask the user again. To run it, set confirm=true and confirm_phrase=\"{need}\"."
        )
    return None


def _api(method: str, path: str, params: dict[str, Any], server: str, max_chars: int,
         confirm: bool = False, phrase: str = "", body: bytes | None = None,
         timeout: int = 30) -> str:
    tier = classify_api(method, path, params)
    names, err = _targets(server, tier == "read")
    if err:
        return "ERROR: " + err
    what = f"{method.upper()} {path}\nParameters: {json.dumps(params)}"
    blocked = _gate(tier, what, confirm, phrase, path, names[0])
    if blocked:
        return blocked
    if (server or "").strip().lower() == "all":
        return "\n\n".join(
            f"=== {n} ===\n{_render(_request(method, path, params, n, body, timeout), max_chars)}"
            for n in names)
    return _render(_request(method, path, params, names[0], body, timeout), max_chars)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def _ssh_settings(server: str) -> dict[str, Any]:
    host = _setting(server, "PIKVM_SSH_HOST")
    if not host:
        if server == DEFAULT_SERVER:
            url = os.environ.get("PIKVM_URL", "")
        else:
            url = os.environ.get(f"PIKVM_URL_{_key(server)}", "")
        host = urllib.parse.urlparse(url if "://" in url else "https://" + url).hostname or ""
    return {
        "host": host,
        "port": int(_setting(server, "PIKVM_SSH_PORT", "22") or 22),
        "user": _setting(server, "PIKVM_SSH_USER", "root"),
        "password": _secret(server, "PIKVM_SSH_PASSWORD"),
        "key": _setting(server, "PIKVM_SSH_KEY"),
    }


def _ssh_connect(server: str):
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("The paramiko package is missing. Install pikvm-mcp again.") from exc
    s = _ssh_settings(server)
    if not s["host"]:
        raise RuntimeError("No SSH host. Set PIKVM_URL (or PIKVM_SSH_HOST).")
    if not s["password"] and not s["key"]:
        need = "PIKVM_SSH_PASSWORD" if server == DEFAULT_SERVER else f"PIKVM_SSH_PASSWORD_{_key(server)}"
        raise RuntimeError(f"Set {need} (or PIKVM_SSH_KEY) to use the server side tools.")
    client = paramiko.SSHClient()
    # A home LAN device. The host key is accepted on first use.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            s["host"], port=s["port"], username=s["user"],
            password=s["password"] or None, key_filename=s["key"] or None,
            timeout=15, banner_timeout=15, auth_timeout=15,
            allow_agent=False, look_for_keys=False)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(_scrub(f"SSH to {s['host']} failed: {exc}", s["password"])) from exc
    return client, s


def _ssh_exec(server: str, command: str, timeout: int = 60) -> dict[str, Any]:
    """Run one command. Returns ok, out, err, code."""
    try:
        client, s = _ssh_connect(server)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return {"ok": True, "out": _scrub(out, s["password"]),
                "err": _scrub(err, s["password"]), "code": code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": _scrub(f"SSH command failed: {exc}", s["password"])}
    finally:
        client.close()


RW = "(command -v rw >/dev/null 2>&1 && rw) || mount -o remount,rw / ; mount -o remount,rw /boot 2>/dev/null; true"
RO = "(command -v ro >/dev/null 2>&1 && ro) || mount -o remount,ro / ; mount -o remount,ro /boot 2>/dev/null; true"


def _ssh_read_file(server: str, path: str) -> dict[str, Any]:
    try:
        client, s = _ssh_connect(server)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        sftp = client.open_sftp()
        try:
            with sftp.open(path, "r") as fh:
                return {"ok": True, "text": fh.read().decode("utf-8", "replace")}
        except FileNotFoundError:
            return {"ok": True, "text": None}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": _scrub(f"Could not read {path}: {exc}", s["password"])}
    finally:
        client.close()


def _ssh_write_file(server: str, path: str, text: str, validate: str) -> dict[str, Any]:
    """Back up, write, validate (restore on failure), always set the disk back to read-only."""
    try:
        client, s = _ssh_connect(server)
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}

    def run(cmd: str, timeout: int = 60) -> tuple[str, str, int]:
        _, o, e = client.exec_command(cmd, timeout=timeout)
        out, err = o.read().decode("utf-8", "replace"), e.read().decode("utf-8", "replace")
        return out, err, o.channel.recv_exit_status()

    stamp = time.strftime("%Y%m%d%H%M%S")
    backup = f"{path}.bak-{stamp}"
    try:
        run(RW)
        sftp = client.open_sftp()
        existed = True
        try:
            sftp.stat(path)
        except FileNotFoundError:
            existed = False
        if existed:
            _, err, code = run(f"cp -p {shlex.quote(path)} {shlex.quote(backup)}")
            if code != 0:
                return {"ok": False, "error": f"Could not make a backup, nothing changed: {err.strip()}"}
        with sftp.open(path, "w") as fh:
            fh.write(text.encode("utf-8"))
        note = ""
        if validate:
            out, err, code = run(validate)
            if code != 0:
                if existed:
                    run(f"cp -p {shlex.quote(backup)} {shlex.quote(path)}")
                else:
                    run(f"rm -f {shlex.quote(path)}")
                return {"ok": False, "error": (
                    "The new file failed the check, so the old file was put back.\n"
                    f"Check output: {(err or out).strip()[:800]}")}
            note = "Check passed (kvmd -m)."
        return {"ok": True, "backup": backup if existed else None, "note": note}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": _scrub(f"Could not write {path}: {exc}", s["password"])}
    finally:
        try:
            run(RO)
        except Exception:  # noqa: BLE001
            pass
        client.close()


def _fmt_ssh(res: dict[str, Any], max_chars: int) -> str:
    if not res.get("ok"):
        return "ERROR: " + res.get("error", "unknown error")
    text = res["out"]
    if res["err"].strip():
        text += ("\n[stderr]\n" + res["err"]) if text else res["err"]
    if res["code"] != 0:
        text += f"\n[exit code {res['code']}]"
    text = text.strip("\n") or "(no output)"
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... cut at {max_chars} characters."
    return text


# ---------------------------------------------------------------------------
# Built-in list of the web API, so Claude knows the paths
# ---------------------------------------------------------------------------

ENDPOINTS: list[tuple[str, str, str, str]] = [
    # (group, method, path, parameters)
    ("system", "GET", "/api/info", "fields=auth,extras,fan,hw,meta,system"),
    ("system", "GET", "/api/log", "seek (lines back). follow is always off here"),
    ("hid", "GET", "/api/hid", ""),
    ("hid", "POST", "/api/hid/set_params", "keyboard_output=usb|ps2|disabled, mouse_output=usb|usb_win98|usb_rel|ps2|disabled, jiggler=bool"),
    ("hid", "POST", "/api/hid/set_connected", "connected=bool"),
    ("hid", "POST", "/api/hid/reset", ""),
    ("hid", "GET", "/api/hid/keymaps", ""),
    ("hid", "POST", "/api/hid/print", "body=text, limit, keymap, slow, delay"),
    ("hid", "POST", "/api/hid/events/send_shortcut", "keys=ControlLeft,AltLeft,Delete"),
    ("hid", "POST", "/api/hid/events/send_key", "key, state, finish"),
    ("hid", "POST", "/api/hid/events/send_mouse_button", "button=left|middle|right|up|down, state"),
    ("hid", "POST", "/api/hid/events/send_mouse_move", "to_x, to_y"),
    ("hid", "POST", "/api/hid/events/send_mouse_relative", "delta_x, delta_y"),
    ("hid", "POST", "/api/hid/events/send_mouse_wheel", "delta_x, delta_y"),
    ("atx", "GET", "/api/atx", ""),
    ("atx", "POST", "/api/atx/power", "action=on|off|off_hard|reset_hard, wait"),
    ("atx", "POST", "/api/atx/click", "button=power|power_long|reset, wait"),
    ("msd", "GET", "/api/msd", ""),
    ("msd", "POST", "/api/msd/write_remote", "url, image, timeout"),
    ("msd", "POST", "/api/msd/set_params", "image, cdrom, rw"),
    ("msd", "POST", "/api/msd/set_connected", "connected=bool"),
    ("msd", "POST", "/api/msd/remove", "image"),
    ("msd", "POST", "/api/msd/reset", ""),
    ("gpio", "GET", "/api/gpio", ""),
    ("gpio", "POST", "/api/gpio/switch", "channel, state, wait"),
    ("gpio", "POST", "/api/gpio/pulse", "channel, delay, wait"),
    ("streamer", "GET", "/api/streamer", ""),
    ("streamer", "GET", "/api/streamer/snapshot", "see pikvm_snapshot"),
    ("streamer", "GET", "/api/streamer/ocr", ""),
    ("switch", "GET", "/api/switch", ""),
    ("switch", "POST", "/api/switch/set_active", "port"),
    ("switch", "POST", "/api/switch/set_active_prev", ""),
    ("switch", "POST", "/api/switch/set_active_next", "(only on a PiKVM Switch)"),
    ("switch", "POST", "/api/switch/set_beacon", "state, port, uplink, downlink"),
    ("switch", "POST", "/api/switch/set_port_params", "port, edid_id, dummy, name, atx_click_power_delay, atx_click_power_long_delay, atx_click_reset_delay"),
    ("switch", "POST", "/api/switch/reset", "unit, bootloader"),
    ("switch", "POST", "/api/switch/edids/create", "name, data"),
    ("switch", "POST", "/api/switch/edids/change", "id, name, data"),
    ("switch", "POST", "/api/switch/edids/remove", "id"),
    ("switch", "POST", "/api/switch/atx/power", "port, action"),
    ("switch", "POST", "/api/switch/atx/click", "port, button"),
    ("export", "GET", "/api/export/prometheus/metrics", ""),
]


# ---------------------------------------------------------------------------
# Tools: app side (web API)
# ---------------------------------------------------------------------------

SERVER_HELP = ("server: which PiKVM, when this tool has several (see pikvm_servers). "
               "Use \"all\" for read-only calls.")


@mcp.tool()
def pikvm_servers() -> str:
    """List the PiKVMs this tool can reach.

    Shows names, addresses and whether SSH is set up. Never shows passwords.
    """
    names = _server_names() or [DEFAULT_SERVER]
    lines = []
    for n in names:
        try:
            url, user, _ = _web_config(n)
            web = f"{url} (user {user})"
        except RuntimeError as exc:
            web = f"NOT SET UP: {exc}"
        s = _ssh_settings(n)
        ssh = (f"ssh {s['user']}@{s['host']}:{s['port']}" if (s["password"] or s["key"]) and s["host"]
               else "ssh not set up")
        lines.append(f"- {n}: {web}; {ssh}")
    return "\n".join(lines)


@mcp.tool()
def pikvm_endpoints(query: str = "", group: str = "") -> str:
    """List the PiKVM web API paths this tool knows, with their options.

    query: a word to look for. group: system, hid, atx, msd, gpio, streamer, switch, export.
    Use pikvm_call to run one.
    """
    q, g = query.lower().strip(), group.lower().strip()
    rows = [e for e in ENDPOINTS
            if (not g or e[0] == g) and (not q or q in (e[2] + " " + e[3]).lower())]
    if not rows:
        return "No match. Groups: system, hid, atx, msd, gpio, streamer, switch, export."
    return "\n".join(f"{m} {p}" + (f"  ({a})" if a else "") for _, m, p, a in rows)


@mcp.tool()
def pikvm_info(fields: str = "system,hw,meta", server: str = "", max_chars: int = 12000) -> str:
    """Show PiKVM details: version, hardware, health (throttling, temperature), name.

    fields: any of auth, extras, fan, hw, meta, system (comma separated).
    """
    return _api("GET", "/api/info", {"fields": fields}, server, max_chars)


@mcp.tool()
def pikvm_status(server: str = "", max_chars: int = 12000) -> str:
    """One look at the target machine: power (ATX), screen (streamer), keyboard and mouse (HID),
    and virtual drive (MSD).
    """
    names, err = _targets(server, True)
    if err:
        return "ERROR: " + err
    parts = []
    for n in names:
        block = {}
        for label, path in (("atx", "/api/atx"), ("streamer", "/api/streamer"),
                            ("hid", "/api/hid"), ("msd", "/api/msd")):
            r = _request("GET", path, None, n)
            block[label] = r.get("data") if r.get("ok") else "ERROR: " + r.get("error", "")
        text = json.dumps(block, indent=1, ensure_ascii=False)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... cut."
        parts.append(f"=== {n} ===\n{text}" if len(names) > 1 else text)
    return "\n\n".join(parts)


@mcp.tool()
def pikvm_call(
    method: str,
    path: str,
    params: dict[str, Any] | None = None,
    body: str = "",
    confirm: bool = False,
    confirm_phrase: str = "",
    server: str = "",
    max_chars: int = 12000,
) -> str:
    """Call any PiKVM web API path (see pikvm_endpoints).

    method: GET or POST (DELETE too). path: starts with /api/. params: query options.
    Reads run right away. Changes need confirm=true after the user says yes.
    Power off, reset, deleting images and similar also need confirm_phrase equal to the path.
    Login and websocket paths are blocked.
    """
    method = method.upper().strip()
    if method not in ("GET", "POST", "DELETE"):
        return "ERROR: method must be GET, POST or DELETE."
    if not path.startswith("/api/") or ".." in path:
        return "ERROR: path must start with /api/ (see pikvm_endpoints)."
    if path.startswith(BLOCKED_API_PREFIXES):
        return "ERROR: that path is blocked. The tool signs in by itself."
    params = dict(params or {})
    if path.rstrip("/") == "/api/log":
        params["follow"] = False
    return _api(method, path, params, server, max_chars, confirm, confirm_phrase,
                body.encode("utf-8") if body else None)


@mcp.tool()
def pikvm_power(
    action: str = "status",
    confirm: bool = False,
    confirm_phrase: str = "",
    server: str = "",
) -> str:
    """Power control of the target machine through ATX.

    action: status, on, off (soft, like a short press), off_hard (cut power, long press),
    reset_hard, click_power, click_power_long, click_reset.
    Everything except status and on can shut the machine down or restart it.
    Those need confirm=true and confirm_phrase equal to the path shown in the reply.
    """
    action = action.lower().strip()
    if action == "status":
        return _api("GET", "/api/atx", {}, server, 12000)
    if action in ("on", "off", "off_hard", "reset_hard"):
        return _api("POST", "/api/atx/power", {"action": action, "wait": True},
                    server, 12000, confirm, confirm_phrase)
    if action in ("click_power", "click_power_long", "click_reset"):
        return _api("POST", "/api/atx/click", {"button": action.removeprefix("click_"), "wait": True},
                    server, 12000, confirm, confirm_phrase)
    return "ERROR: action must be status, on, off, off_hard, reset_hard, click_power, click_power_long or click_reset."


@mcp.tool()
def pikvm_snapshot(
    ocr: bool = False,
    max_width: int = 1280,
    save: bool = False,
    server: str = "",
):
    """Take a picture of what the target machine is showing on its screen.

    ocr: also read the text on the screen. max_width: shrink the picture (pixels).
    save: also keep the full size picture as a file on this computer.
    Needs one PiKVM (not "all").
    """
    names, err = _targets(server, True)
    if err or len(names) != 1:
        return "ERROR: " + (err or "Pick one PiKVM for a screenshot.")
    name = names[0]
    result = _request("GET", "/api/streamer/snapshot",
                      {"allow_offline": False, "preview": 1 if max_width else 0,
                       "preview_max_width": max_width or None, "preview_quality": 80},
                      name, raw=True, timeout=45)
    if not result.get("ok"):
        return "ERROR: " + result.get("error", "no picture")
    data = result["bytes"]
    if save:
        label = "" if name == DEFAULT_SERVER else f"{_key(name).lower()}-"
        full = _request("GET", "/api/streamer/snapshot", {"allow_offline": False}, name,
                        raw=True, timeout=45)
        target = _download_dir() / f"{int(time.time())}-{label}screen.jpg"
        target.write_bytes(full["bytes"] if full.get("ok") else data)
    if ocr:
        text = _request("GET", "/api/streamer/ocr", None, name, raw=True, timeout=45)
        if text.get("ok"):
            return f"Screen text (OCR):\n{text['bytes'].decode('utf-8', 'replace')[:6000]}"
    return Image(data=data, format="jpeg")


@mcp.tool()
def pikvm_type(
    text: str = "",
    shortcut: str = "",
    keymap: str = "",
    slow: bool = False,
    confirm: bool = False,
    server: str = "",
) -> str:
    """Type on the target machine like a USB keyboard.

    text: text to type. shortcut: keys together, like ControlLeft,AltLeft,Delete.
    Give one of them. This changes what the machine does, so it needs confirm=true.
    """
    if bool(text) == bool(shortcut):
        return "ERROR: give either text or shortcut."
    if shortcut:
        return _api("POST", "/api/hid/events/send_shortcut", {"keys": shortcut},
                    server, 4000, confirm)
    params: dict[str, Any] = {"limit": 0, "slow": slow}
    if keymap:
        params["keymap"] = keymap
    return _api("POST", "/api/hid/print", params, server, 4000, confirm,
                body=text.encode("utf-8"), timeout=120)


@mcp.tool()
def pikvm_msd(
    action: str = "status",
    image: str = "",
    url: str = "",
    cdrom: bool = True,
    read_write: bool = False,
    confirm: bool = False,
    confirm_phrase: str = "",
    server: str = "",
) -> str:
    """The virtual USB drive (mass storage) that shows an ISO or disk image to the target.

    action: status (also lists images), select (pick an image), connect, disconnect,
    download (fetch an image from url into the PiKVM), remove (delete an image).
    select: image name, cdrom=true for ISO, read_write=true for a writable disk.
    download: url, plus image for the file name. remove needs confirm_phrase equal to the path.
    """
    action = action.lower().strip()
    if action == "status":
        return _api("GET", "/api/msd", {}, server, 12000)
    if action == "select":
        if not image:
            return "ERROR: give the image name."
        return _api("POST", "/api/msd/set_params",
                    {"image": image, "cdrom": cdrom, "rw": read_write},
                    server, 4000, confirm, confirm_phrase)
    if action in ("connect", "disconnect"):
        return _api("POST", "/api/msd/set_connected", {"connected": action == "connect"},
                    server, 4000, confirm, confirm_phrase)
    if action == "download":
        if not url:
            return "ERROR: give the url."
        return _api("POST", "/api/msd/write_remote",
                    {"url": url, "image": image or None, "timeout": 30},
                    server, 4000, confirm, confirm_phrase, timeout=1800)
    if action == "remove":
        if not image:
            return "ERROR: give the image name."
        return _api("POST", "/api/msd/remove", {"image": image},
                    server, 4000, confirm, confirm_phrase)
    return "ERROR: action must be status, select, connect, disconnect, download or remove."


@mcp.tool()
def pikvm_log(lines: int = 200, server: str = "", max_chars: int = 12000) -> str:
    """Show the PiKVM (kvmd) log. Newest lines at the end.

    lines: how many lines from the end to keep.
    """
    names, err = _targets(server, True)
    if err:
        return "ERROR: " + err
    out = []
    for n in names:
        r = _request("GET", "/api/log", {"follow": False}, n, timeout=45)
        if r.get("ok"):
            text = r["data"] if isinstance(r["data"], str) else json.dumps(r["data"])
            tail = "\n".join(text.splitlines()[-max(1, lines):])
            if len(tail) > max_chars:
                tail = "... cut ...\n" + tail[-max_chars:]
        else:
            tail = "ERROR: " + r.get("error", "")
        out.append(f"=== {n} ===\n{tail}" if len(names) > 1 else tail)
    return "\n\n".join(out)


# ---------------------------------------------------------------------------
# Tools: server side (SSH)
# ---------------------------------------------------------------------------

@mcp.tool()
def pikvm_ssh(
    command: str,
    confirm: bool = False,
    confirm_phrase: str = "",
    timeout: int = 60,
    server: str = "",
    max_chars: int = 12000,
) -> str:
    """Run one command on the PiKVM over SSH (as root).

    Safe read-only commands run right away (cat of /etc/kvmd files, systemctl status,
    journalctl, df, uptime, ip a, vcgencmd measure_temp, kvmd -m, pacman -Q, ls, and pipes
    into head, tail, grep, wc). Anything else needs confirm=true after the user says yes.
    Risky ones (rm, reboot, pacman, pikvm-update, passwd, stopping services and similar)
    also need confirm_phrase equal to the first word of the command.
    Files with passwords or keys are blocked.
    The PiKVM disk is read-only. To change a config file use pikvm_config_write instead.
    """
    tier = classify_ssh(command)
    if tier == "blocked":
        return "ERROR: that command is empty or touches a file with passwords or keys. It is blocked."
    names, err = _targets(server, tier == "read")
    if err:
        return "ERROR: " + err
    first = shlex.split(command)[0] if command.strip() else ""
    blocked = _gate(tier, f"Command: {command}", confirm, confirm_phrase, first, names[0],
                    extra="The PiKVM disk is read-only unless rw is run first.\n")
    if blocked:
        return blocked
    timeout = max(5, min(int(timeout), 900))
    if (server or "").strip().lower() == "all":
        return "\n\n".join(f"=== {n} ===\n{_fmt_ssh(_ssh_exec(n, command, timeout), max_chars)}"
                           for n in names)
    return _fmt_ssh(_ssh_exec(names[0], command, timeout), max_chars)


@mcp.tool()
def pikvm_system_info(server: str = "", max_chars: int = 12000) -> str:
    """A read-only health check over SSH: OS, kvmd version, uptime, disk, memory, temperature,
    throttling, USB gadget, network addresses, and the state of the main PiKVM services.
    """
    script = (
        "echo '## os'; cat /etc/os-release | head -3; uname -a; uptime; "
        "echo '## kvmd'; pacman -Q | grep -E '^(kvmd|ustreamer|janus)' ; "
        "echo '## disk'; df -h / /boot /var/lib/kvmd/msd 2>/dev/null; "
        "echo '## memory'; free -h; "
        "echo '## health'; vcgencmd measure_temp 2>/dev/null; vcgencmd get_throttled 2>/dev/null; "
        "echo '## network'; ip -br a; "
        "echo '## services'; systemctl is-active kvmd kvmd-nginx kvmd-otg kvmd-vnc kvmd-ipmi "
        "kvmd-janus kvmd-webterm kvmd-oled kvmd-fan 2>/dev/null"
    )
    names, err = _targets(server, True)
    if err:
        return "ERROR: " + err
    out = []
    for n in names:
        res = _ssh_exec(n, script, 60)
        text = _fmt_ssh(res, max_chars)
        out.append(f"=== {n} ===\n{text}" if len(names) > 1 else text)
    return "\n\n".join(out)


@mcp.tool()
def pikvm_config_read(path: str = "/etc/kvmd/override.yaml", server: str = "",
                      max_chars: int = 20000) -> str:
    """Read a PiKVM config file over SSH.

    Default is /etc/kvmd/override.yaml, the file where your own settings live.
    Allowed: text files in /etc/kvmd/, /boot/config.txt, /boot/cmdline.txt, /etc/hostname.
    Files with passwords, keys or 2FA secrets are blocked.
    """
    why = config_path_ok(path)
    if why:
        return "ERROR: " + why
    names, err = _targets(server, True)
    if err:
        return "ERROR: " + err
    out = []
    for n in names:
        res = _ssh_read_file(n, posixpath.normpath(path))
        if not res.get("ok"):
            text = "ERROR: " + res.get("error", "")
        elif res["text"] is None:
            text = f"(file {path} does not exist yet)"
        else:
            text = res["text"]
            if len(text) > max_chars:
                text = text[:max_chars] + f"\n... cut at {max_chars} characters."
        out.append(f"=== {n} ===\n{text}" if len(names) > 1 else text)
    return "\n\n".join(out)


@mcp.tool()
def pikvm_config_write(
    path: str,
    content: str,
    restart: str = "",
    confirm: bool = False,
    confirm_phrase: str = "",
    server: str = "",
) -> str:
    """Replace a PiKVM config file over SSH. Needs one PiKVM.

    path: same allowed files as pikvm_config_read. content: the WHOLE new file
    (read it first with pikvm_config_read, change it, send it all back).
    The first call shows a diff and does nothing. After the user says yes, call again
    with confirm=true.
    The tool makes the disk writable, saves a backup next to the file (.bak-date),
    writes the file, runs "kvmd -m" to check /etc/kvmd/*.yaml files (and puts the old file back
    if the check fails), then makes the disk read-only again.
    restart: optional service to restart after a good write, usually kvmd.
    A restart of kvmd, kvmd-nginx or kvmd-otg also needs confirm_phrase equal to the service name.
    """
    why = config_path_ok(path)
    if why:
        return "ERROR: " + why
    if re.search(r"(?im)^\s*(passwd|password|secret)\s*:\s*\S", content):
        return ("ERROR: the content looks like it has a password or secret in it. "
                "Put secrets in place by hand, not through the chat.")
    names, err = _targets(server, False)
    if err:
        return "ERROR: " + err
    name = names[0]
    path = posixpath.normpath(path)
    if restart and not UNIT_RE.match(restart):
        return "ERROR: restart must be a service name like kvmd."

    current = _ssh_read_file(name, path)
    if not current.get("ok"):
        return "ERROR: " + current.get("error", "")
    old = current["text"] or ""
    if old == content:
        return "Nothing to do. The file already has this content."
    diff = "".join(difflib.unified_diff(
        old.splitlines(True), content.splitlines(True),
        fromfile=f"{path} (now)", tofile=f"{path} (new)", n=2))
    if len(diff) > 6000:
        diff = diff[:6000] + "\n... diff cut ...\n"

    tier = "change"
    need = path
    if restart and classify_service("restart", restart) == "destructive":
        tier, need = "destructive", restart
    what = f"Write file: {path}" + (f"\nThen restart: {restart}" if restart else "")
    blocked = _gate(tier, what, confirm, confirm_phrase, need, name,
                    extra=f"Diff:\n{diff or '(new file)'}\n")
    if blocked:
        return blocked

    validate = "kvmd -m >/dev/null" if (path.startswith("/etc/kvmd/") and path.endswith((".yaml", ".yml"))) else ""
    res = _ssh_write_file(name, path, content, validate)
    if not res.get("ok"):
        return "ERROR: " + res.get("error", "")
    msg = [f"Wrote {path}.", res.get("note", "")]
    if res.get("backup"):
        msg.append(f"Backup: {res['backup']}")
    if restart:
        r = _ssh_exec(name, f"systemctl restart {shlex.quote(restart)}", 60)
        msg.append(f"Restart {restart}: " + ("done." if r.get("ok") and r["code"] == 0
                                              else _fmt_ssh(r, 1000)))
    else:
        msg.append("Not restarted. Most /etc/kvmd settings need: systemctl restart kvmd.")
    return "\n".join(m for m in msg if m)


@mcp.tool()
def pikvm_service(
    action: str,
    unit: str,
    confirm: bool = False,
    confirm_phrase: str = "",
    server: str = "",
) -> str:
    """Check or control a service on the PiKVM over SSH.

    action: status, start, restart, reload, enable, disable, stop.
    unit: for example kvmd, kvmd-nginx, kvmd-vnc, kvmd-ipmi, kvmd-janus, kvmd-webterm.
    Status runs right away. Stop and disable, and any restart of kvmd, kvmd-nginx,
    kvmd-otg, ssh or networking, need confirm_phrase equal to the unit name.
    """
    action = action.lower().strip()
    if action not in ("status", "start", "restart", "reload", "enable", "disable", "stop"):
        return "ERROR: action must be status, start, restart, reload, enable, disable or stop."
    if not UNIT_RE.match(unit):
        return "ERROR: unit must look like kvmd or kvmd-nginx."
    tier = classify_service(action, unit)
    names, err = _targets(server, tier == "read")
    if err:
        return "ERROR: " + err
    blocked = _gate(tier, f"systemctl {action} {unit}", confirm, confirm_phrase, unit, names[0])
    if blocked:
        return blocked
    cmd = f"systemctl {'status --no-pager -n 15' if action == 'status' else action} {shlex.quote(unit)}"
    if (server or "").strip().lower() == "all":
        return "\n\n".join(f"=== {n} ===\n{_fmt_ssh(_ssh_exec(n, cmd, 90), 8000)}" for n in names)
    return _fmt_ssh(_ssh_exec(names[0], cmd, 90), 8000)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
