"""Tests the write/backup/validate/restore flow with a fake SSH client. Run: python tests/test_ssh_write.py"""
import io, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pikvm_mcp import server as s  # noqa: E402

fails = 0
def check(name, cond):
    global fails
    print(("ok   " if cond else "FAIL ") + name); fails += 0 if cond else 1


class Chan:
    def __init__(self, code): self.code = code
    def recv_exit_status(self): return self.code
class Stream:
    def __init__(self, text, code=0): self.b, self.channel = text.encode(), Chan(code)
    def read(self): return self.b
class FH:
    def __init__(self, fs, path, mode): self.fs, self.path, self.mode = fs, path, mode
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self): return self.fs.files[self.path].encode()
    def write(self, b):
        assert self.fs.rw, "wrote while disk was read-only"
        self.fs.files[self.path] = b.decode()
class Sftp:
    def __init__(self, fs): self.fs = fs
    def stat(self, p):
        if p not in self.fs.files: raise FileNotFoundError(p)
    def open(self, p, mode):
        if mode == "r" and p not in self.fs.files: raise FileNotFoundError(p)
        return FH(self.fs, p, mode)
class Client:
    def __init__(self, validate_ok=True):
        self.files = {"/etc/kvmd/override.yaml": "old\n"}; self.rw = False; self.log = []; self.validate_ok = validate_ok
    def open_sftp(self): return Sftp(self)
    def close(self): pass
    def exec_command(self, cmd, timeout=60):
        self.log.append(cmd)
        if cmd == s.RW: self.rw = True
        elif cmd == s.RO: self.rw = False
        elif cmd.startswith("cp -p "):
            a, b = cmd[6:].replace("'", "").split(" ")
            self.files[b] = self.files[a]
        elif cmd.startswith("rm -f "): self.files.pop(cmd[6:].replace("'", ""), None)
        elif cmd.startswith("kvmd -m"): return None, Stream("", 0 if self.validate_ok else 1), Stream("" if self.validate_ok else "bad yaml")
        return None, Stream(""), Stream("")


def run(path, text, validate, ok=True):
    c = Client(ok)
    s._ssh_connect = lambda server: (c, {"password": "", "host": "x"})
    return c, s._ssh_write_file("d", path, text, validate)

c, r = run("/etc/kvmd/override.yaml", "new\n", "kvmd -m >/dev/null")
check("good write ok", r["ok"] and c.files["/etc/kvmd/override.yaml"] == "new\n")
check("backup made", r["backup"] and c.files[r["backup"]] == "old\n")
check("disk back to read-only", c.rw is False and c.log[0] == s.RW and c.log[-1] == s.RO)
c, r = run("/etc/kvmd/override.yaml", "broken\n", "kvmd -m >/dev/null", ok=False)
check("bad yaml refused", not r["ok"] and "bad yaml" in r["error"])
check("old file restored", c.files["/etc/kvmd/override.yaml"] == "old\n")
check("read-only even after failure", c.rw is False)
c, r = run("/etc/kvmd/web.css", "a{}\n", "")
check("new file, no backup", r["ok"] and r["backup"] is None and c.files["/etc/kvmd/web.css"] == "a{}\n")
c, r = run("/etc/kvmd/web.css", "a{}\n", "kvmd -m >/dev/null", ok=False)
check("new file removed on failed check", not r["ok"] and "/etc/kvmd/web.css" not in c.files)
print("\nFAILED: %d" % fails if fails else "\nALL PASSED"); sys.exit(1 if fails else 0)
