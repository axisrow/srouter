#!/usr/bin/env python3
"""Independent, read-only snapshot of the disposable macOS uninstall VM."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import plistlib
import stat
import subprocess
from pathlib import Path


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout, "err": p.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"rc": None, "out": "", "err": str(exc)}


def file_info(path):
    try:
        s = path.lstat()
        data = {"mode": stat.S_IMODE(s.st_mode), "uid": s.st_uid, "gid": s.st_gid,
                "type": stat.S_IFMT(s.st_mode)}
        if path.is_symlink():
            data["link"] = os.readlink(path)
        elif path.is_file():
            data["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        data["acl"] = run(["/bin/ls", "-lde", str(path)])["out"].splitlines()[1:]
        data["xattrs"] = run(["/usr/bin/xattr", "-s", "-l", "-x", str(path)])["out"]
        return data
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {"error": str(exc)}


def snapshot(root):
    model = run(["/usr/sbin/sysctl", "-n", "hw.model"])["out"].strip()
    if os.environ.get("SROUTER_VM_ACCEPTANCE") != "1" or not model.startswith("VirtualMac"):
        raise SystemExit("REFUSED: expected SROUTER_VM_ACCEPTANCE=1 inside a disposable Apple VM")
    home = Path.home()
    commands = {}
    commands["os"] = run(["/usr/bin/sw_vers"])
    commands["services"] = run(["/opt/homebrew/bin/brew", "services", "list"])
    commands["packages"] = run(["/opt/homebrew/bin/brew", "list", "--formula", "--versions"])
    commands["socks"] = run(["/usr/sbin/scutil", "--proxy"])
    commands["resolver"] = run(["/usr/sbin/scutil", "--dns"])
    commands["routes"] = run(["/usr/sbin/netstat", "-rn"])
    commands["processes"] = run(["/bin/ps", "-axo", "pid,uid,command"])
    commands["root_services"] = run(["/usr/bin/sudo", "-n", "/opt/homebrew/bin/brew", "services", "list"])
    commands["codex_user"] = run(["/usr/bin/dscl", ".", "-read", "/Users/_srouter_codex", "UniqueID", "PrimaryGroupID", "UserShell", "NFSHomeDirectory"])
    commands["pf_status"] = run(["/usr/bin/sudo", "-n", "/sbin/pfctl", "-s", "info"])
    commands["pf_anchors"] = run(["/usr/bin/sudo", "-n", "/sbin/pfctl", "-a", "*", "-s", "Anchors"])
    for anchor in ("com.apple/srouter_isolate", "com.apple/srouter_isolate/codex"):
        commands["pf_" + anchor] = run(["/usr/bin/sudo", "-n", "/sbin/pfctl", "-a", anchor, "-sr"])
    services = run(["/usr/sbin/networksetup", "-listallnetworkservices"])
    commands["network_services"] = services
    for service in services["out"].splitlines()[1:]:
        service = service.lstrip("*")
        for option in ("-getdnsservers", "-getwebproxy", "-getsecurewebproxy",
                       "-getsocksfirewallproxy", "-getautoproxyurl", "-getproxybypassdomains"):
            commands[option + ":" + service] = run(["/usr/sbin/networksetup", option, service])
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                "all_proxy", "NO_PROXY", "no_proxy"):
        commands["env:" + key] = run(["/bin/launchctl", "getenv", key])
    labels = {"com.srouter.dashboard", "com.srouter.watchdog", "com.srouter.netprobe",
              "com.srouter.codenv", "com.srouter.isolate", "com.srouter.isolate-escape",
              "com.srouter.isolate-refresh", "com.srouter.privoxy", "com.srouter.privoxy.audit"}
    labels.update(prefix + name for prefix in ("homebrew.mxcl.", "sh.brew.") for name in ("xray", "privoxy", "dnsmasq"))
    files = {}
    trees = [home / "bin", home / "Library/LaunchAgents",
             Path("/Library/LaunchDaemons"), Path("/Library/PrivilegedHelperTools"),
             Path("/Library/Application Support/srouter"), Path("/Library/Logs/srouter"),
             Path("/opt/homebrew/etc/privoxy"), Path("/opt/homebrew/etc/xray"),
             Path("/opt/homebrew/etc/dnsmasq.d"), Path("/etc/ppp"), Path("/etc/resolver"),
             home / "Library/Application Support/srouter"]
    paths = [home / ".zshrc", home / ".gitconfig", home / ".claude/settings.json",
             home / "Library/Application Support/Code/User/settings.json",
             home / "Library/Application Support/Cursor/User/settings.json",
             home / "Library/Application Support/VSCodium/User/settings.json",
             home / "Library/Application Support/go/env", Path("/opt/homebrew/etc/dnsmasq.conf"),
             Path("/etc/pf.conf"), root / "srouter.local.json", root / "srouter_config.py"]
    for tree in trees:
        paths.append(tree)
        if tree.exists() and not tree.is_symlink():
            paths.extend(tree.rglob("*"))
    for path in sorted(set(paths)):
        if path.parent == Path("/Library/LaunchDaemons") and not path.name.startswith(("com.srouter.", "homebrew.mxcl.")):
            continue
        if path.parent == Path("/Library/PrivilegedHelperTools") and not path.name.startswith("com.srouter."):
            continue
        files[str(path)] = file_info(path)
        if path.suffix == ".plist" and path.exists():
            try:
                label = plistlib.loads(path.read_bytes()).get("Label", "")
                if label.startswith("com.srouter."):
                    labels.add(label)
            except (OSError, ValueError, plistlib.InvalidFileException):
                pass
    for label in sorted(labels):
        for domain in (f"gui/{os.getuid()}", "system"):
            cmd = ["/bin/launchctl", "print", f"{domain}/{label}"]
            if domain == "system":
                cmd = ["/usr/bin/sudo", "-n"] + cmd
            commands["launchd:" + domain + "/" + label] = run(cmd)
    return {"captured_at": datetime.now(timezone.utc).isoformat(), "model": model, "root": str(root), "commands": commands, "files": files}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = snapshot(args.root.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    args.out.chmod(0o600)
    print(args.out)
