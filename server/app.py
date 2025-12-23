#!/usr/bin/env python3
"""
Podium Display Server – STABLE FINAL
Smoothcomp / OddFox compatible
"""

import json
import os
from flask import send_from_directory, abort
import shlex
import shutil
import subprocess
import sys
import time
import tempfile
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from typing import Dict, Any, Tuple

import requests
from bs4 import BeautifulSoup
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.utils import secure_filename

# --------------------------------------------------
# App
# --------------------------------------------------

app = Flask(__name__)
# -------------------------------------------------------------------
# Fallback asset serving (offline mode for kiosks)
# -------------------------------------------------------------------

FALLBACK_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fallback")
)

@app.route("/assets/fallback/<path:filename>")
def serve_fallback_asset(filename):
    allowed_files = {
        "offline.html",
        "offline.png",
    }

    if filename not in allowed_files:
        abort(404)

    return send_from_directory(
        FALLBACK_DIR,
        filename,
        conditional=True
    )


app.secret_key = "CHANGE_THIS_TO_ANY_RANDOM_STRING"

# --------------------------------------------------
# Config
# --------------------------------------------------

CONFIG_FILE = Path("podium_config.json")

DEFAULT_CONFIG = {
    "podium_url": "",
    "refresh_interval": 30,
    "cache_ttl": 15,
    "session_cookies": {},
    "last_updated": None,
    "screensaver_enabled": False,
    "screensaver_timeout": 60,  # seconds
    "screensaver_use_same": True,
    "screensaver_image_all": "",
    "screensaver_image_first": "",
    "screensaver_image_second": "",
    "screensaver_image_third": "",
    "pi_hosts": [],
    "pi_user": "pi",
    "pi_password": "",
    "ssh_key_path": "",
    "offline_fallback_filename": "offline.svg",
}

config = dict(DEFAULT_CONFIG)
SCREENSAVER_TIMEOUT = 1 * 60  # seconds
SCREENSAVER_DIR = Path("static/screensaver")
OFFLINE_FALLBACK_DIR = Path("/opt/kiosk-fallback")
OFFLINE_FALLBACK_DEFAULT_NAME = "offline.svg"
OFFLINE_FALLBACK_HTML = OFFLINE_FALLBACK_DIR / "offline.html"
HEARTBEAT_INTERVAL = 5  # seconds between heartbeats from displays
DISPLAY_HEARTBEAT_WARN = 60  # age (s) before showing a warning
DISPLAY_HEARTBEAT_TTL = 180  # age (s) until a display is considered offline

# --------------------------------------------------
# Cache
# --------------------------------------------------

cache_lock = Lock()
podium_cache = {
    "url": "",
    "fetched_at": 0.0,
    "data": None,
    "error": None,
}
name_change_times = {
    "first": 0.0,
    "second": 0.0,
    "third": 0.0,
}
name_change_version = 0
display_status: Dict[int, Dict[str, Any]] = {1: {}, 2: {}, 3: {}}

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def load_config():
    if CONFIG_FILE.exists():
        try:
            config.update(json.loads(CONFIG_FILE.read_text()))
        except Exception:
            pass

def save_config():
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def record_name_changes(prev_data: Dict[str, Any] | None, new_data: Dict[str, Any], stamp: float) -> None:
    """Track when each podium name last changed to drive the screensaver."""
    global name_change_version
    changed = False
    for slot in ("first", "second", "third"):
        prev_name = (prev_data or {}).get(slot, {}).get("name", None)
        new_name = new_data.get(slot, {}).get("name", "")

        if not new_name and not prev_name:
            continue

        if prev_name is None or new_name != prev_name or not name_change_times.get(slot, 0.0):
            name_change_times[slot] = stamp
            changed = True

    if changed:
        name_change_version += 1


def select_screensaver_image(pos: int) -> str | None:
    """Return a relative static URL for the screensaver image to use for a given position."""
    # Use shared image if configured and present
    if config.get("screensaver_use_same"):
        fname = (config.get("screensaver_image_all") or "").strip()
        if fname:
            path = SCREENSAVER_DIR / fname
            if path.exists():
                return f"/static/screensaver/{fname}"

    # Fall back to per-position images
    field = {1: "screensaver_image_first", 2: "screensaver_image_second", 3: "screensaver_image_third"}[pos]
    fname = (config.get(field) or "").strip()
    if fname:
        path = SCREENSAVER_DIR / fname
        if path.exists():
            return f"/static/screensaver/{fname}"

    return None


def write_offline_fallback_page(image_name: str | None = None) -> None:
    """Ensure offline fallback assets exist with a black background that shows the image."""
    OFFLINE_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
    img_name = image_name or config.get("offline_fallback_filename") or OFFLINE_FALLBACK_DEFAULT_NAME
    html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Offline fallback</title>
  <style>
    html, body {{ margin: 0; padding: 0; width: 100%; height: 100%; background: #000; display: flex; align-items: center; justify-content: center; overflow: hidden; }}
    img {{ max-width: 90vw; max-height: 90vh; }}
  </style>
</head>
<body>
  <img src="{img}" alt="Offline fallback">
</body>
</html>
""".format(img=img_name)
    write_file_with_sudo(OFFLINE_FALLBACK_HTML, html)


def ensure_local_offline_dir() -> tuple[bool, str]:
    """Make sure /opt/kiosk-fallback exists locally with permissive perms."""
    try:
        OFFLINE_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
        OFFLINE_FALLBACK_DIR.chmod(0o775)
        return True, ""
    except PermissionError:
        # Attempt sudo without prompting
        try:
            result = subprocess.run(
                ["sudo", "-n", "mkdir", "-p", str(OFFLINE_FALLBACK_DIR)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout or "").strip()
                return False, msg or "sudo mkdir failed"
            subprocess.run(
                ["sudo", "-n", "chmod", "775", str(OFFLINE_FALLBACK_DIR)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return True, ""
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)


def write_file_with_sudo(path: Path, content: str) -> None:
    """Write text to a path, falling back to sudo if needed."""
    try:
        path.write_text(content, encoding="utf-8")
        return
    except PermissionError:
        pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        subprocess.run(
            ["sudo", "-n", "cp", str(tmp_path), str(path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        subprocess.run(
            ["sudo", "-n", "chmod", "664", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception as e:
        raise PermissionError(f"sudo copy failed: {e}") from e
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def save_upload_with_sudo(upload, dest_path: Path) -> None:
    """Save an upload to dest_path, falling back to sudo copy if needed."""
    try:
        upload.save(dest_path)
        return
    except PermissionError:
        pass

    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
        upload.save(tmp)
        tmp_path = Path(tmp.name)
    try:
        subprocess.run(
            ["sudo", "-n", "cp", str(tmp_path), str(dest_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        subprocess.run(
            ["sudo", "-n", "chmod", "664", str(dest_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception as e:
        raise PermissionError(f"sudo copy failed: {e}") from e
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def update_display_status(pos: int, payload: Dict[str, Any]) -> None:
    stamp = time.time()
    display_status[pos] = {
        "last_seen": stamp,
        "url": payload.get("url", ""),
        "resolution": payload.get("resolution", ""),
        "online": True,
    }

def get_pi_hosts() -> list[str]:
    raw_hosts = config.get("pi_hosts") or []
    if isinstance(raw_hosts, str):
        hosts = [h.strip() for h in raw_hosts.splitlines() if h.strip()]
    else:
        hosts = [str(h).strip() for h in raw_hosts if str(h).strip()]
    if not hosts:
        hosts = [
            "podium1@podium1.local",
            "podium2@podium2.local",
            "podium3@podium3.local",
        ]
    return hosts


def ssh_run(host: str, remote_cmd: str, timeout: int = 15) -> Tuple[bool, str]:
    """Run a remote command over SSH using configured credentials."""
    user = (config.get("pi_user") or "pi").strip()
    target = host if "@" in host else f"{user}@{host}"
    key_path = os.path.expanduser(config.get("ssh_key_path") or "")
    password = config.get("pi_password", "").strip()

    if password and not key_path:
        if not shutil.which("sshpass"):
            return False, "sshpass not installed on server (needed for password auth)"
        cmd = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
        ]
    else:
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
        ]
        if key_path:
            cmd += ["-i", key_path]
    cmd += [target, remote_cmd]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()
        success = result.returncode == 0
        message = output or error or f"Exit code {result.returncode}"
        return success, message
    except Exception as e:
        return False, str(e)


def scp_copy(host: str, local_path: Path, remote_path: str, timeout: int = 20) -> Tuple[bool, str]:
    """Copy a file to a host using scp with the same credentials as ssh_run."""
    user = (config.get("pi_user") or "pi").strip()
    target = host if "@" in host else f"{user}@{host}"
    key_path = os.path.expanduser(config.get("ssh_key_path") or "")
    password = config.get("pi_password", "").strip()

    if password and not key_path:
        if not shutil.which("sshpass"):
            return False, "sshpass not installed on server (needed for password auth)"
        cmd = [
            "sshpass",
            "-p",
            password,
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ]
    else:
        cmd = [
            "scp",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ]
        if key_path:
            cmd += ["-i", key_path]

    cmd += [str(local_path), f"{target}:{remote_path}"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()
        success = result.returncode == 0
        message = output or error or f"Exit code {result.returncode}"
        return success, message
    except Exception as e:
        return False, str(e)


def push_offline_fallback_to_pis(image_path: Path, html_path: Path) -> list[Dict[str, Any]]:
    """Push offline fallback image + html to all configured Pi hosts."""
    hosts = get_pi_hosts()
    password = (config.get("pi_password") or "").strip()
    results: list[Dict[str, Any]] = []
    img_name = image_path.name
    html_name = html_path.name
    tmp_img = f"/tmp/{img_name}"
    tmp_html = f"/tmp/{html_name}"
    for host in hosts:
        if password:
            remote_prepare = (
                f"echo {shlex.quote(password)} | sudo -S sh -c 'mkdir -p /opt/kiosk-fallback && chmod 775 /opt/kiosk-fallback'"
            )
        else:
            remote_prepare = (
                "if command -v sudo >/dev/null 2>&1; then "
                "sudo -n mkdir -p /opt/kiosk-fallback && sudo -n chmod 775 /opt/kiosk-fallback || mkdir -p /opt/kiosk-fallback; "
                "else mkdir -p /opt/kiosk-fallback; fi"
            )
        ok_mkdir, msg_mkdir = ssh_run(host, remote_prepare, timeout=10)
        if not ok_mkdir:
            results.append({"host": host, "ok": False, "error": f"mkdir failed: {msg_mkdir}"})
            continue

        ok_img, msg_img = scp_copy(host, image_path, tmp_img)
        if not ok_img:
            results.append({"host": host, "ok": False, "error": f"image copy failed: {msg_img}"})
            continue

        ok_html, msg_html = scp_copy(host, html_path, tmp_html)
        if not ok_html:
            results.append({"host": host, "ok": False, "error": f"html copy failed: {msg_html}"})
            continue

        if password:
            remote_move = (
                f"echo {shlex.quote(password)} | sudo -S sh -c '"
                f"mv {shlex.quote(tmp_img)} /opt/kiosk-fallback/{shlex.quote(img_name)} && "
                f"mv {shlex.quote(tmp_html)} /opt/kiosk-fallback/offline.html && "
                f"chmod 664 /opt/kiosk-fallback/{shlex.quote(img_name)} /opt/kiosk-fallback/offline.html'"
            )
        else:
            remote_move = (
                "if command -v sudo >/dev/null 2>&1; then "
                f"sudo -n mv {shlex.quote(tmp_img)} /opt/kiosk-fallback/{shlex.quote(img_name)} && "
                f"sudo -n mv {shlex.quote(tmp_html)} /opt/kiosk-fallback/offline.html && "
                f"sudo -n chmod 664 /opt/kiosk-fallback/{shlex.quote(img_name)} /opt/kiosk-fallback/offline.html; "
                "else "
                f"mv {shlex.quote(tmp_img)} /opt/kiosk-fallback/{shlex.quote(img_name)} && "
                f"mv {shlex.quote(tmp_html)} /opt/kiosk-fallback/offline.html && "
                f"chmod 664 /opt/kiosk-fallback/{shlex.quote(img_name)} /opt/kiosk-fallback/offline.html; "
                "fi"
            )

        ok_move, msg_move = ssh_run(host, remote_move, timeout=10)
        results.append({"host": host, "ok": ok_move, "error": "" if ok_move else f"move failed: {msg_move}"})
    return results


def fetch_wifi_status() -> list[Dict[str, Any]]:
    """Return current network info (wifi/ethernet) for each configured Pi host."""
    hosts = get_pi_hosts()
    remote_script = """
wifi=$(iwgetid -r 2>/dev/null || true)
nm=$(nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev status 2>/dev/null || true)
wired=""
while IFS=: read -r dev typ state conn; do
  [ -z "$dev" ] && continue
  if [ "$state" = "connected" ]; then
    if [ "$typ" = "ethernet" ] && [ -z "$wired" ]; then wired="$conn"; fi
    if [ "$typ" = "wifi" ] && [ -z "$wifi" ]; then wifi="$conn"; fi
  fi
done <<<"$nm"
printf "wifi=%s|wired=%s\n" "${wifi:-none}" "${wired:-none}"
"""
    remote_cmd = f"bash -lc {shlex.quote(remote_script)}"
    results = []
    for host in hosts:
        ok, output = ssh_run(host, remote_cmd, timeout=10)
        wifi_name = ""
        wired_name = ""
        if ok:
            try:
                parts = (output or "").split("|")
                for p in parts:
                    if p.startswith("wifi="):
                        wifi_name = p.replace("wifi=", "", 1)
                    elif p.startswith("wired="):
                        wired_name = p.replace("wired=", "", 1)
            except Exception:
                pass

        connection = "unknown"
        network = ""
        if wifi_name and wifi_name != "none":
            connection = "wifi"
            network = wifi_name
        elif wired_name and wired_name != "none":
            connection = "ethernet"
            network = wired_name
        else:
            network = wifi_name or wired_name or (output if ok else "")

        results.append(
            {
                "host": host,
                "ok": ok,
                "network": network,
                "connection": connection,
                "error": "" if ok else (output or "Unable to read network"),
            }
        )
    return results


def apply_wifi_credentials(ssid: str, password: str) -> list[Dict[str, Any]]:
    """Push WiFi credentials to all configured Pi hosts."""
    hosts = get_pi_hosts()
    if not hosts:
        return []

    if not ssid or not password:
        return [
            {"host": host, "ok": False, "error": "Missing SSID/password", "network": ""}
            for host in hosts
        ]

    # Guard against invalid PSKs so we don't spam nmcli with errors.
    def _psk_valid(psk: str) -> bool:
        # WPA/WPA2: 8–63 ASCII chars, or exactly 64 hex digits.
        if 8 <= len(psk) <= 63:
            return True
        if len(psk) == 64:
            try:
                int(psk, 16)
                return True
            except ValueError:
                return False
        return False

    if not _psk_valid(password):
        return [
            {
                "host": host,
                "ok": False,
                "error": "WiFi password must be 8-63 characters (or 64 hex)",
                "network": "",
            }
            for host in hosts
        ]

    remote_script = (
        f"SSID={shlex.quote(ssid)}; PSK={shlex.quote(password)}; "
        "iface=wlan0; "
        "if ! command -v nmcli >/dev/null 2>&1; then echo \"nmcli missing\"; exit 1; fi; "
        "run() { sudo -n nmcli \"$@\" || nmcli \"$@\"; }; "
        "run_timeout() { timeout 20 sudo -n nmcli \"$@\" || timeout 20 nmcli \"$@\"; }; "
        "run connection delete \"$SSID\" >/dev/null 2>&1 || true; "
        "log=\"\"; "
        "add_out=$(run connection add type wifi ifname \"$iface\" con-name \"$SSID\" ssid \"$SSID\" wifi-sec.key-mgmt wpa-psk wifi-sec.psk \"$PSK\" connection.autoconnect yes 2>&1); "
        "add_rc=$?; "
        "if [ $add_rc -ne 0 ] && ! echo \"$add_out\" | grep -qi \"already.*exists\"; then "
        "  log=\"$log add failed: $add_out\"; "
        "else "
        "  mod_out=$(run connection modify \"$SSID\" connection.autoconnect yes 2>&1 || true); "
        "  reload_out=$(run connection reload 2>&1 || true); "
        "  log=\"$log add: $add_out | mod: $mod_out | reload: $reload_out\"; "
        "fi; "
        "ssid_now=$(iwgetid -r 2>/dev/null); "
        "if [ -z \"$ssid_now\" ]; then ssid_now=$(nmcli -t -f ACTIVE,SSID dev wifi | grep \"^yes:\" | head -n1 | cut -d: -f2-); fi; "
        "printf \"saved for %s (current: %s)\\n%s\\n\" \"$SSID\" \"${ssid_now:-unknown}\" \"$log\"; "
        "exit 0"
    )
    wrapped_cmd = f"bash -lc {shlex.quote(remote_script)}"

    results: list[Dict[str, Any]] = []
    for host in hosts:
        wrapper = (
            "if command -v timeout >/dev/null 2>&1; then "
            f"timeout 20 {wrapped_cmd}; "
            "else "
            f"{wrapped_cmd}; "
            "fi"
        )
        ok, output = ssh_run(host, wrapper, timeout=40)
        results.append(
            {
                "host": host,
                "ok": ok,
                "network": output if ok else "",
                "error": "" if ok else (output or "Failed to apply WiFi"),
            }
        )
    return results


def compute_display_view(pos: int, data: Dict[str, Any] | None) -> Dict[str, Any]:
    """Compute what should be on a display: name, state (podium/saver/blank), and idle timings."""
    now = time.time()
    key = {1: "first", 2: "second", 3: "third"}[pos]
    athlete = data.get(key, {}) if data else {}
    name = athlete.get("name", "") if isinstance(athlete, dict) else ""

    slot_change = name_change_times.get(key, 0.0)
    slot_ref = slot_change or podium_cache.get("fetched_at", 0.0) or now
    idle_for_slot = now - slot_ref

    first_change = name_change_times.get("first", 0.0)
    first_ref = first_change or podium_cache.get("fetched_at", 0.0) or now
    idle_for_first = now - first_ref

    screensaver_enabled = bool(config.get("screensaver_enabled"))
    try:
        screensaver_timeout = int(config.get("screensaver_timeout") or SCREENSAVER_TIMEOUT)
    except Exception:
        screensaver_timeout = SCREENSAVER_TIMEOUT

    shared_screensaver = data is not None and screensaver_enabled and idle_for_first >= screensaver_timeout
    no_name_missing = pos in (2, 3) and not name

    if shared_screensaver:
        state = "screensaver"
    elif no_name_missing:
        state = "blank"
    else:
        state = "podium"

    display_name = "Screensaver" if state == "screensaver" else (name or "")

    return {
        "state": state,
        "display_name": display_name or "—",
        "idle_first": idle_for_first,
        "idle_slot": idle_for_slot,
        "screensaver_active": state == "screensaver",
    }


def summarize_display_status() -> Dict[int, Dict[str, Any]]:
    data = podium_cache.get("data")
    now = time.time()
    summary: Dict[int, Dict[str, Any]] = {}
    for pos in (1, 2, 3):
        info = display_status.get(pos, {}) or {}
        last_seen = info.get("last_seen", 0.0) or 0.0
        age = now - last_seen if last_seen else float("inf")
        online = age < DISPLAY_HEARTBEAT_TTL if last_seen else False

        # Derive what's currently intended to be on-screen.
        current = compute_display_view(pos, data)
        warn = ""
        needs_attention = False
        if not online:
            warn = "No heartbeat"
            needs_attention = True
        elif age > DISPLAY_HEARTBEAT_WARN:
            warn = f"Heartbeat slow ({int(age)}s old)"
            needs_attention = True

        summary[pos] = {
            "online": online,
            "last_seen": datetime.fromtimestamp(last_seen).strftime("%H:%M:%S") if last_seen else "never",
            "url": info.get("url") or "—",
            "resolution": info.get("resolution") or "unknown",
            "needs_attention": needs_attention,
            "warning": warn or "—",
            "name": current["display_name"],
            "state": current["state"],
        }
    return summary

# --------------------------------------------------
# Scraper (OddFox / Smoothcomp)
# --------------------------------------------------

def scrape_podium(url: str, cookies: Dict[str, str]) -> Dict[str, Any]:
    headers = {
        "User-Agent": "Mozilla/5.0 (PodiumDisplay)",
        "Accept-Language": "en-GB,en;q=0.9",
    }

    session = requests.Session()
    for k, v in cookies.items():
        session.cookies.set(k, v)

    r = session.get(url, headers=headers, timeout=15)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    podium = soup.select_one("#podium")
    if not podium:
        raise RuntimeError("Podium container not found")

    category_el = podium.select_one("h1")
    category = category_el.get_text(strip=True) if category_el else "Podium"

    def extract(place: str):
        item = podium.select_one(f"article.item.{place}") or podium.select_one(f".item.{place}")
        if not item:
            return {"name": "", "club": "", "country": ""}

        # ---- NAME (OddFox layout) ----
        name = ""
        h4 = item.select_one("h4")
        if h4:
            name = h4.get_text(" ", strip=True)

        # ---- CLUB (often missing) ----
        club_el = (
            item.select_one(".club")
            or item.select_one(".team")
            or item.select_one(".academy")
        )
        club = club_el.get_text(" ", strip=True) if club_el else ""

        # ---- COUNTRY / FLAG NORMALIZATION ----
        country = ""
        flag = item.select_one("span.flag-icon")
        if flag:
            for cls in flag.get("class", []):
                if cls.startswith("flag-icon-") and cls != "flag-icon":
                    raw = cls.replace("flag-icon-", "").lower()

                    # UK sub-flags → local SVGs (match filenames)
                    if raw in ("gb-eng", "eng"):
                        country = "gb-eng"
                    elif raw in ("gb-sct", "sct"):
                        country = "gb-sct"
                    elif raw in ("gb-wls", "wls"):
                        country = "gb-wls"
                    elif raw.startswith("gb"):
                        country = "gb"
                    else:
                        country = raw

                    break

        return {
            "name": name,
            "club": club,
            "country": country,
        }


    data = {
        "category": category,
        "first": extract("first"),
        "second": extract("second"),
        "third": extract("third"),
    }

    # Allow partial podiums but require at least one name
    if not any(
        p["name"] for p in (data["first"], data["second"], data["third"])
    ):
        raise RuntimeError("Podium loaded but no athlete names visible yet")

    return data

def get_podium_data(force=False) -> Tuple[Any, str | None]:
    url = config.get("podium_url", "").strip()
    if not url:
        return None, "No podium URL configured"

    ttl = int(config.get("cache_ttl", 15))
    now = time.time()

    with cache_lock:
        prev_data = podium_cache["data"]
        if (
            not force
            and podium_cache["data"]
            and podium_cache["url"] == url
            and now - podium_cache["fetched_at"] < ttl
        ):
            return podium_cache["data"], None

        prev_data = podium_cache["data"]
        try:
            data = scrape_podium(url, config.get("session_cookies", {}))
            fetched_at = time.time()
            record_name_changes(prev_data, data, fetched_at)
            podium_cache.update(
                {"url": url, "data": data, "fetched_at": fetched_at, "error": None}
            )
            config["last_updated"] = now_str()
            save_config()
            return data, None
        except Exception as e:
            podium_cache.update(
                {"url": url, "data": prev_data, "fetched_at": now, "error": str(e)}
            )
            return prev_data, str(e)

# --------------------------------------------------
# Templates
# --------------------------------------------------

DISPLAY_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{{ position }}</title>

<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #000;
  color: #fff;
  width: 100vw;
  height: 100vh;
  position: relative;
  overflow: hidden;
  font-family: system-ui, Arial, sans-serif;
}

#stage {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 1920px;
  height: 1080px;
  transform-origin: center center;
  overflow: visible;
}

.container { 
  position: absolute;
  top: 3%;
  left: 50%;
  transform: translate(-50%, 0);
  text-align: center;
  width: 1920px;
}

.header-row {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}
.header-row::before {
  content: "";
  display: block;
  width: 8rem;
}
.position-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.medal {
  width: 15rem;
  height: 15rem;
  animation: bounce 2s infinite;
  margin-bottom: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}
.medal img {
  width: 100%;
  height: 100%;
  display: block;
  object-fit: contain;
}
@keyframes bounce {
  0%,100% { transform: translateY(0); }
  50% { transform: translateY(-15px); }
}

.position {
  font-size: 14rem;
  font-weight: 900;
  animation: drop .8s forwards;
  opacity: 0;
  text-align: center;
}
@keyframes drop {
  to { opacity: 1; transform: translateY(0); }
}

.card-wrapper {
  margin-top: 3rem;
  display: flex;
  justify-content: center;
}

.card {
  padding: 3rem 3.5rem;
  border-radius: 2.5rem;
  border: 8px solid {{ accent }};
  box-shadow: 0 0 40px {{ glow }};
  animation: card .9s forwards .4s, glowPulse 2.4s ease-in-out infinite 1.2s;
  opacity: 0;
  display: inline-block;
}
@keyframes card {
  to { opacity: 1; transform: scale(1); }
}
@keyframes glowPulse {
  0%, 100% { box-shadow: 0 0 40px {{ glow }}; }
  50% { box-shadow: 0 0 80px {{ glow }}; }
}

.name-row { 
  display: flex;
  align-items: center;
  gap: 2rem;
  white-space: nowrap;
}
.name { 
  font-size: 7.5rem;
  font-weight: 900; 
  line-height: 1.15;
}
.club { 
  font-size: 3.5rem;
  opacity: .85; 
  margin-top: 1rem;
  text-align: center;
}

.flag img {
  width: 6rem;
  height: auto;
  border-radius: .4rem;
  box-shadow: 0 0 20px rgba(0,0,0,.7);
  flex-shrink: 0;
}

.category { 
  margin-top: 5rem;
  font-size: 5rem;
  opacity: .7;
  text-align: center;
  margin-bottom: 8rem;
}

.footer {
  position: absolute;
  bottom: 1rem;
  right: 1rem;
  font-size: 1rem;
  opacity: .6;
}

.logo {
  position: absolute;
  bottom: 1rem;
  left: 50%;
  transform: translateX(-50%);
}

.logo img {
  max-width: 25rem;
  height: auto;
  display: block;
}
</style>
</head>
<body>
<div id="stage">
  <div class="container">
    <div class="header-row">
      <div class="position-wrap">
        <div class="position">{{ position }}</div>
      </div>
      <div class="medal">
        <img src="{{ medal_src }}" alt="{{ position }} medal">
      </div>
    </div>

    <div class="card-wrapper">
      <div class="card">
        <div class="name-row">
          <div class="name">{{ name }}</div>
          {% if country %}
          <div class="flag">
            <img src="/static/flags/{{ country }}.svg"
                 onerror="this.src='/static/flags/gb.svg'">
          </div>
          {% endif %}
        </div>
        {% if club %}<div class="club">{{ club }}</div>{% endif %}
      </div>
    </div>

    <div class="category">{{ category }}</div>
  </div>

  <div class="footer">Updated: {{ updated }}</div>
  <div class="logo">
    <img src="/static/logo/oddfox.png" alt="OddFox logo">
  </div>
</div>

<script>
const stageWidth = 1920;
const stageHeight = 1080;

function fitStage() {
  const stage = document.getElementById("stage");
  if (!stage) return;
  const scaleX = window.innerWidth / stageWidth;
  const scaleY = window.innerHeight / stageHeight;
  const scale = Math.min(scaleX, scaleY);
  stage.style.transform = `translate(-50%, -50%) scale(${scale})`;
}
window.addEventListener("resize", fitStage);
fitStage();

const refreshMs = {{ refresh * 1000 }};
let nextReload = refreshMs;

{% if screensaver_enabled %}
const saverMs = ({{ screensaver_timeout }} * 1000) - ({{ idle_for }} * 1000);
if (saverMs > 0) {
  nextReload = Math.min(nextReload, saverMs);
}
{% endif %}

setTimeout(() => location.reload(), Math.max(3000, nextReload));

const initialVersion = {{ name_version }};
const pollMs = Math.max(3000, {{ poll_interval * 1000 }});
setInterval(() => {
  fetch("/api/name-version")
    .then(r => r.json())
    .then(d => {
      if (typeof d.version === "number" && d.version !== initialVersion) {
        location.reload();
      }
    })
    .catch(() => {});
}, pollMs);

function sendHeartbeat() {
  fetch("/api/display-heartbeat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      pos: {{ pos }},
      url: window.location.href,
      resolution: `${window.screen.width}x${window.screen.height}`,
    }),
  }).catch(() => {});
}
sendHeartbeat();
setInterval(sendHeartbeat, {{ heartbeat_interval * 1000 }});
</script>
</body>
</html>
"""

SCREENSAVER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{{ position }} idle</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #000;
  color: #fff;
  height: 100vh;
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}
.wrapper {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100vw;
  height: 100vh;
}
.wrapper img {
  width: 100%;
  height: 100%;
  object-fit: contain;
}
.fallback {
  color: #888;
  font-size: 1.4rem;
  letter-spacing: .04em;
}
</style>
</head>
<body>
  <div class="wrapper">
    {% if image_url %}
      <img src="{{ image_url }}" alt="Screensaver">
    {% else %}
      <div class="fallback">Screensaver enabled – upload a PNG in admin</div>
    {% endif %}
  </div>
<script>
const refreshMs = {{ refresh * 1000 }};
let nextReload = refreshMs;

{% if screensaver_enabled %}
const saverMs = ({{ screensaver_timeout }} * 1000) - ({{ idle_for }} * 1000);
if (saverMs > 0) {
  nextReload = Math.min(nextReload, saverMs);
}
{% endif %}

setTimeout(() => location.reload(), Math.max(3000, nextReload));

const initialVersion = {{ name_version }};
const pollMs = Math.max(3000, {{ poll_interval * 1000 }});
setInterval(() => {
  fetch("/api/name-version")
    .then(r => r.json())
    .then(d => {
      if (typeof d.version === "number" && d.version !== initialVersion) {
        location.reload();
      }
    })
    .catch(() => {});
}, pollMs);

function sendHeartbeat() {
  fetch("/api/display-heartbeat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      pos: {{ pos }},
      url: window.location.href,
      resolution: `${window.screen.width}x${window.screen.height}`,
    }),
  }).catch(() => {});
}
sendHeartbeat();
setInterval(sendHeartbeat, 10000);
</script>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Podium Admin</title>
<style>
:root {
  --bg: #f5f7fb;
  --card: #fff;
  --border: #d0d7de;
  --text: #1f2328;
  --muted: #6e7781;
  --accent: #0f6bff;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--text); }
.page { max-width: 1100px; margin: 0 auto; padding: 28px; }
.page-header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 18px; }
.page-header h1 { margin: 0; display: flex; align-items: center; gap: 0.35rem; font-size: 1.6rem; }
.subhead { color: var(--muted); margin: 4px 0 0; }
.section { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; margin-bottom: 14px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04); }
.section h2 { margin: 0 0 10px; font-size: 1.1rem; }
.section h3 { margin: 12px 0 8px; font-size: 1rem; }
.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
label { font-weight: 600; font-size: 0.95rem; display: block; margin-bottom: 6px; }
input[type="text"], input[type="password"], input[type="number"], textarea { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 0.95rem; background: #fff; color: var(--text); }
textarea { min-height: 120px; resize: vertical; }
.check-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.small { color: var(--muted); font-size: 0.85rem; }
.buttons { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.btn { border: 1px solid var(--border); background: #eef3fb; color: #0f2d5d; padding: 10px 14px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: background 0.15s, border-color 0.15s; }
.btn.primary { background: linear-gradient(90deg, #0f6bff, #4f9bff); border-color: #0f6bff; color: #fff; }
.btn.danger { background: #ffe7e7; border-color: #ffb3b3; color: #a01313; }
.btn:disabled { opacity: 0.6; cursor: not-allowed; }
.table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.95rem; }
.table th, .table td { border: 1px solid var(--border); padding: 8px 10px; text-align: left; }
.table th { background: #f6f8fa; font-weight: 700; }
.muted { color: var(--muted); }
.links { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.tag { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; background: #f0f4ff; border: 1px solid var(--border); border-radius: 6px; text-decoration: none; color: inherit; }
.message { background: #e9f2ff; border: 1px solid #b6d3ff; padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; display: inline-block; }
.field-stack { display: flex; flex-direction: column; gap: 12px; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.medal-icon { width: 1.3em; height: 1.3em; vertical-align: -0.2em; margin-right: 0.3em; }
</style>
</head>
<body>
<div class="page">
  <div class="page-header">
    <div>
      <h1>🏆 Podium Admin</h1>
      <p class="subhead">Manage display data, screensaver, and device connectivity.</p>
    </div>
    <button id="restart-btn" type="button" class="btn danger">Restart server</button>
  </div>

  {% if message %}<div class="message"><strong>{{ message }}</strong></div>{% endif %}

  <form method="POST" enctype="multipart/form-data">
    <div class="section">
      <h2>Display source</h2>
      <div class="grid">
        <div>
          <label>Podium URL</label>
          <input name="podium_url" type="text" value="{{ config.podium_url }}">
        </div>
        <div>
          <label>Session Cookies (JSON)</label>
          <textarea name="session_cookies">{{ cookies }}</textarea>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Data refresh</h2>
      <div class="grid">
        <div>
          <label>Refresh Interval (sec)</label>
          <input type="number" name="refresh_interval" value="{{ config.refresh_interval }}">
        </div>
        <div>
          <label>Cache TTL (sec)</label>
          <input type="number" name="cache_ttl" value="{{ config.cache_ttl }}">
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Screensaver</h2>
      <div class="field-stack">
        <label class="check-row">
          <input type="checkbox" name="screensaver_enabled" value="1" {% if config.screensaver_enabled %}checked{% endif %}>
          Enable screensaver
        </label>
        <div class="grid">
          <div>
            <label>Timeout (seconds)</label>
            <input type="number" name="screensaver_timeout" min="10" value="{{ config.screensaver_timeout }}">
          </div>
          <div>
            <label class="check-row" style="margin: 0;">
              <input type="checkbox" name="screensaver_use_same" value="1" {% if config.screensaver_use_same %}checked{% endif %}>
              Use same image for all positions
            </label>
          </div>
        </div>
        <div class="grid">
          <div>
            <h3>All positions</h3>
            <input type="file" name="screensaver_image_all" accept="image/png">
            <div class="small">Current: {{ config.screensaver_image_all or "none" }}</div>
          </div>
          <div>
            <h3>Per-position images</h3>
            <div class="field-stack">
              <div>
                <label>1st</label>
                <input type="file" name="screensaver_image_first" accept="image/png">
                <div class="small">Current: {{ config.screensaver_image_first or "none" }}</div>
              </div>
              <div>
                <label>2nd</label>
                <input type="file" name="screensaver_image_second" accept="image/png">
                <div class="small">Current: {{ config.screensaver_image_second or "none" }}</div>
              </div>
              <div>
                <label>3rd</label>
                <input type="file" name="screensaver_image_third" accept="image/png">
                <div class="small">Current: {{ config.screensaver_image_third or "none" }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Offline fallback</h2>
      <div class="field-stack">
        <input type="file" name="offline_svg" accept="image/*">
        <div class="small">Uploads to /opt/kiosk-fallback/offline.&lt;ext&gt; (svg/png/jpg/gif/webp) and rewrites offline.html with a black background showing the image.</div>
      </div>
    </div>

    <div class="section">
      <h2>Actions</h2>
      <div class="buttons">
        <button type="submit" class="btn primary">Save</button>
        <button type="submit" name="action" value="test" class="btn">Test scrape</button>
      </div>
    </div>

    <div class="section">
      <h2>Displays</h2>
      <div class="links">
        <a class="tag" href="/display/1" target="_blank"><img class="medal-icon" src="/static/logo/1.svg" alt="1st medal">1st</a>
        <a class="tag" href="/display/2" target="_blank"><img class="medal-icon" src="/static/logo/2.svg" alt="2nd medal">2nd</a>
        <a class="tag" href="/display/3" target="_blank"><img class="medal-icon" src="/static/logo/3.svg" alt="3rd medal">3rd</a>
      </div>
      <p class="muted">Last updated: {{ config.last_updated }}</p>
    </div>

    <div class="section">
      <h2>Display Status</h2>
      <table class="table" id="status-table">
        <thead>
          <tr><th>Display</th><th>Status</th><th>Last seen</th><th>URL</th><th>Resolution</th><th>Name</th><th>State</th><th>Needs attention</th><th>Warning</th></tr>
        </thead>
        <tbody>
          {% for pos, info in statuses.items() %}
          <tr>
            <td>{{ pos }}</td>
            <td style="color:{{ 'green' if info.online else 'red' }}">{{ 'online' if info.online else 'offline' }}</td>
            <td>{{ info.last_seen }}</td>
            <td>{{ info.url }}</td>
            <td>{{ info.resolution }}</td>
            <td>{{ info.name }}</td>
            <td>{{ info.state }}</td>
            <td style="color:{{ 'red' if info.needs_attention else '#555' }}">{{ 'yes' if info.needs_attention else 'no' }}</td>
            <td>{{ info.warning }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="section">
      <h2>Pi SSH &amp; WiFi</h2>
      <div class="field-stack">
        <div class="grid">
          <div>
            <label>Pi hosts (one per line)</label>
            <textarea name="pi_hosts" style="min-height: 100px;">{{ pi_hosts_text }}</textarea>
            <div class="small">Defaults to podium1@podium1.local, podium2@podium2.local, podium3@podium3.local</div>
          </div>
          <div class="grid">
            <div>
              <label>SSH password (saved as plain text)</label>
              <input type="password" name="pi_password" autocomplete="new-password" value="{{ config.pi_password }}">
            </div>
            <div>
              <label>SSH key path (optional; used if set)</label>
              <input name="ssh_key_path" placeholder="~/.ssh/id_rsa" value="{{ config.ssh_key_path }}">
            </div>
          </div>
        </div>

        <div>
          <h3>Send WiFi credentials</h3>
          <div class="grid">
            <div>
              <label>SSID</label>
              <input name="wifi_ssid" autocomplete="off">
            </div>
            <div>
              <label>Password</label>
              <input type="password" name="wifi_password" autocomplete="new-password">
            </div>
          </div>
          <div class="buttons" style="margin-top: 6px;">
            <button type="submit" name="action" value="send_wifi" class="btn primary">Send WiFi to all Pis</button>
          </div>
        </div>

        {% if wifi_push_results %}
        <div>
          <h3>Last push results</h3>
          <table class="table">
            <thead><tr><th>Host</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>
              {% for row in wifi_push_results %}
              <tr>
                <td>{{ row.host }}</td>
                <td style="color:{{ 'green' if row.ok else 'red' }}">{{ 'ok' if row.ok else 'error' }}</td>
                <td>{{ row.network or row.error }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% endif %}

        <div>
          <div class="section-head">
            <h3 style="margin: 0;">Current WiFi networks</h3>
            <button type="button" id="refresh-wifi" class="btn">Refresh</button>
          </div>
          <table class="table" id="wifi-table">
            <thead><tr><th>Host</th><th>Connection</th><th>Status</th></tr></thead>
            <tbody id="wifi-table-body"></tbody>
          </table>
        </div>
      </div>
    </div>
  </form>
</div>

<script>
function renderStatusTable(rows) {
  const tbody = document.querySelector("#status-table tbody");
  if (!tbody) return;
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.pos}</td>
      <td style="color:${r.online ? 'green' : 'red'}">${r.online ? 'online' : 'offline'}</td>
      <td>${r.last_seen}</td>
      <td>${r.url}</td>
      <td>${r.resolution}</td>
      <td>${r.name}</td>
      <td>${r.state}</td>
      <td style="color:${r.needs_attention ? 'red' : '#555'}">${r.needs_attention ? 'yes' : 'no'}</td>
      <td>${r.warning || '—'}</td>
    </tr>
  `).join("");
}

async function pollStatus() {
  try {
    const res = await fetch("/api/admin/status");
    const data = await res.json();
    renderStatusTable(data.statuses || []);
  } catch (e) {
    // ignore
  }
}
pollStatus();
setInterval(pollStatus, 10000);

function renderWifiTable(rows) {
  const tbody = document.querySelector("#wifi-table-body");
  if (!tbody) return;
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.host}</td>
      <td>${(r.connection || 'unknown') + (r.network ? `: ${r.network}` : '')}</td>
      <td style="color:${r.ok ? 'green' : 'red'}">${r.ok ? 'ok' : (r.error || 'error')}</td>
    </tr>
  `).join("");
}

async function pollWifiStatus() {
  try {
    const res = await fetch("/api/admin/wifi-status");
    const data = await res.json();
    renderWifiTable(data.results || []);
  } catch (e) {
    // ignore
  }
}
pollWifiStatus();
setInterval(pollWifiStatus, 15000);

const refreshWifiBtn = document.querySelector("#refresh-wifi");
if (refreshWifiBtn) {
  refreshWifiBtn.addEventListener("click", pollWifiStatus);
}

const restartBtn = document.querySelector("#restart-btn");
if (restartBtn) {
  restartBtn.addEventListener("click", async () => {
    if (!confirm("Restart the server now?")) return;
    restartBtn.disabled = true;
    restartBtn.textContent = "Restarting…";
    try {
      const res = await fetch("/api/admin/restart", { method: "POST" });
      if (!res.ok) throw new Error();
      restartBtn.textContent = "Restarting… reloading shortly";
      setTimeout(() => location.reload(), 4000);
    } catch (e) {
      restartBtn.disabled = false;
      restartBtn.textContent = "Restart server";
      alert("Restart failed");
    }
  });
}
</script>
</body>
</html>
"""

# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("admin"))

@app.route("/admin", methods=["GET", "POST"])
def admin():
    message = session.pop("message", None)
    notes = []
    wifi_push_results: list[Dict[str, Any]] = session.pop("wifi_push_results", [])

    if request.method == "POST":
        config["podium_url"] = request.form.get("podium_url", "").strip()
        config["refresh_interval"] = int(request.form.get("refresh_interval", 30))
        config["cache_ttl"] = int(request.form.get("cache_ttl", 15))
        config["screensaver_enabled"] = bool(request.form.get("screensaver_enabled"))
        config["screensaver_use_same"] = bool(request.form.get("screensaver_use_same"))
        config["pi_password"] = request.form.get("pi_password", "").strip()
        config["ssh_key_path"] = request.form.get("ssh_key_path", "").strip()

        try:
            config["screensaver_timeout"] = max(
                10, int(request.form.get("screensaver_timeout", config.get("screensaver_timeout", SCREENSAVER_TIMEOUT)))
            )
        except Exception:
            config["screensaver_timeout"] = config.get("screensaver_timeout", SCREENSAVER_TIMEOUT)

        cookies_text = request.form.get("session_cookies", "").strip()
        if cookies_text:
            try:
                config["session_cookies"] = json.loads(cookies_text)
            except Exception as e:
                config["session_cookies"] = {}
                message = f"Cookie JSON error: {e}"
        else:
            config["session_cookies"] = {}

        pi_hosts_text = request.form.get("pi_hosts", "")
        config["pi_hosts"] = [h.strip() for h in pi_hosts_text.splitlines() if h.strip()]

        upload_fields = {
            "screensaver_image_all": "All positions",
            "screensaver_image_first": "1st",
            "screensaver_image_second": "2nd",
            "screensaver_image_third": "3rd",
        }
        for field, label in upload_fields.items():
            upload = request.files.get(field)
            if upload and upload.filename:
                fname = secure_filename(upload.filename)
                if not fname.lower().endswith(".png"):
                    message = f"{label} screensaver image must be a PNG"
                    break
                SCREENSAVER_DIR.mkdir(parents=True, exist_ok=True)
                upload.save(SCREENSAVER_DIR / fname)
                config[field] = fname
                notes.append(f"Uploaded {label}")

        offline_upload = request.files.get("offline_svg")
        if offline_upload and offline_upload.filename and not message:
            fname = secure_filename(offline_upload.filename)
            allowed_exts = {".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp"}
            ext = Path(fname).suffix.lower()
            if ext not in allowed_exts:
                message = "Offline fallback must be an image (svg/png/jpg/gif/webp)"
            else:
                try:
                    ok_dir, err_dir = ensure_local_offline_dir()
                    if not ok_dir:
                        raise PermissionError(err_dir or "Unable to create /opt/kiosk-fallback; try running: sudo mkdir -p /opt/kiosk-fallback && sudo chmod 775 /opt/kiosk-fallback")
                    final_name = f"offline{ext}" if ext else OFFLINE_FALLBACK_DEFAULT_NAME
                    offline_path = OFFLINE_FALLBACK_DIR / final_name
                    save_upload_with_sudo(offline_upload, offline_path)
                    config["offline_fallback_filename"] = final_name
                    write_offline_fallback_page(final_name)
                    push_results = push_offline_fallback_to_pis(offline_path, OFFLINE_FALLBACK_HTML)
                    failed = [r for r in push_results if not r.get("ok")]
                    if failed:
                        fail_hosts = "; ".join(
                            f"{r.get('host', '?')}: {r.get('error') or 'unknown error'}" for r in failed
                        )
                        message = f"Offline fallback saved locally but failed to push: {fail_hosts}"
                    else:
                        notes.append(f"Offline fallback updated and pushed ({ext.lstrip('.')})")
                except Exception as e:
                    message = f"Failed to save offline fallback: {e}"

        save_config()
        podium_cache["data"] = None

        action = request.form.get("action")
        if action == "send_wifi" and not message:
            ssid = request.form.get("wifi_ssid", "").strip()
            password = request.form.get("wifi_password", "").strip()
            if not ssid or not password:
                message = "SSID and password are required to send WiFi credentials"
            else:
                wifi_push_results = apply_wifi_credentials(ssid, password)
                if not wifi_push_results:
                    message = "No Pi hosts configured"
                else:
                    ok_count = sum(1 for r in wifi_push_results if r.get("ok"))
                    fail_count = len(wifi_push_results) - ok_count
                    message = f"WiFi pushed ({ok_count} ok, {fail_count} failed)"
        elif action == "test" and not message:
            data, err = get_podium_data(force=True)
            message = f"OK: {data['category']}" if data else f"Error: {err}"
        elif not message:
            message = "Saved" + (f" ({'; '.join(notes)})" if notes else "")

        session["message"] = message
        session["wifi_push_results"] = wifi_push_results
        return redirect(url_for("admin"))

    cookies = json.dumps(config.get("session_cookies", {}), indent=2)
    pi_hosts_text = "\n".join(get_pi_hosts())
    return render_template_string(
        ADMIN_TEMPLATE,
        config=config,
        cookies=cookies,
        message=message,
        statuses=summarize_display_status(),
        pi_hosts_text=pi_hosts_text,
        wifi_push_results=wifi_push_results,
    )

@app.route("/display/<int:pos>")
def display(pos):
    if pos not in (1, 2, 3):
        abort(404)

    data, _ = get_podium_data()
    key = {1: "first", 2: "second", 3: "third"}[pos]
    athlete = data[key] if data else {}
    position_label = {1: "1st", 2: "2nd", 3: "3rd"}[pos]

    now = time.time()
    slot_change = name_change_times.get(key, 0.0)
    slot_change_ref = slot_change or podium_cache.get("fetched_at", 0.0) or now
    idle_for_slot = now - slot_change_ref

    first_change = name_change_times.get("first", 0.0)
    first_ref = first_change or podium_cache.get("fetched_at", 0.0) or now
    idle_for_first = now - first_ref

    screensaver_enabled = bool(config.get("screensaver_enabled"))
    try:
        screensaver_timeout = int(config.get("screensaver_timeout") or SCREENSAVER_TIMEOUT)
    except Exception:
        screensaver_timeout = SCREENSAVER_TIMEOUT

    no_name_missing = pos in (2, 3) and not athlete.get("name")
    shared_screensaver = data and screensaver_enabled and idle_for_first >= screensaver_timeout
    idle_for_effective = idle_for_first if shared_screensaver else idle_for_slot

    if no_name_missing:
        # If 1st place has triggered the screensaver, join it; otherwise stay black.
        if shared_screensaver:
            image_url = select_screensaver_image(pos)
            return render_template_string(
                SCREENSAVER_TEMPLATE,
                position=position_label,
                idle_minutes=int(idle_for_effective // 60) or 1,
                refresh=config.get("refresh_interval", 30),
                image_url=image_url,
                name_version=name_change_version,
                poll_interval=config.get("cache_ttl", 15),
                screensaver_enabled=screensaver_enabled,
                screensaver_timeout=screensaver_timeout,
                idle_for=idle_for_effective,
            )

        return render_template_string(
            """
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>{{ position }}</title></head>
            <body style="margin:0;background:#000;">
            <script>
            const refreshMs = {{ refresh * 1000 }};
            let nextReload = refreshMs;

            {% if screensaver_enabled %}
            const remainingSaverMs = ({{ screensaver_timeout }} * 1000) - ({{ idle_for }} * 1000);
            if (remainingSaverMs > 0) {
              nextReload = Math.min(nextReload, remainingSaverMs);
            }
            {% endif %}

            setTimeout(() => location.reload(), Math.max(3000, nextReload));
            const initialVersion = {{ name_version }};
            const pollMs = Math.max(3000, {{ poll_interval * 1000 }});
            setInterval(() => {
              fetch("/api/name-version")
                .then(r => r.json())
                .then(d => {
                  if (typeof d.version === "number" && d.version !== initialVersion) {
                    location.reload();
                  }
                })
                .catch(() => {});
            }, pollMs);

            function sendHeartbeat() {
              fetch("/api/display-heartbeat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  pos: {{ pos }},
                  url: window.location.href,
                  resolution: `${window.screen.width}x${window.screen.height}`,
                }),
              }).catch(() => {});
            }
            sendHeartbeat();
            setInterval(sendHeartbeat, {{ heartbeat_interval * 1000 }});
            </script>
            </body>
            </html>
            """,
            refresh=config.get("refresh_interval", 30),
            name_version=name_change_version,
            poll_interval=config.get("cache_ttl", 15),
            screensaver_enabled=screensaver_enabled,
            screensaver_timeout=screensaver_timeout,
            idle_for=idle_for_effective,
            heartbeat_interval=HEARTBEAT_INTERVAL,
            pos=pos,
            position=position_label,
        )

    if shared_screensaver:
        image_url = select_screensaver_image(pos)

        return render_template_string(
            SCREENSAVER_TEMPLATE,
            position=position_label,
            idle_minutes=int(idle_for_effective // 60) or 1,
            refresh=config.get("refresh_interval", 30),
            image_url=image_url,
            name_version=name_change_version,
            poll_interval=config.get("cache_ttl", 15),
            screensaver_enabled=screensaver_enabled,
            screensaver_timeout=screensaver_timeout,
            idle_for=idle_for_effective,
            heartbeat_interval=HEARTBEAT_INTERVAL,
            pos=pos,
        )

    accent = {1: "#FFD700", 2: "#C0C0C0", 3: "#CD7F32"}[pos]
    glow = {
        1: "rgba(255,215,0,.6)",
        2: "rgba(192,192,192,.6)",
        3: "rgba(205,127,50,.6)",
    }[pos]

    return render_template_string(
        DISPLAY_TEMPLATE,
        position=position_label,
        medal_src={1: "/static/logo/1.svg", 2: "/static/logo/2.svg", 3: "/static/logo/3.svg"}[pos],
        accent=accent,
        glow=glow,
        name=athlete.get("name", "Loading…"),
        club=athlete.get("club", ""),
        country=athlete.get("country", ""),
        category=data["category"] if data else "Loading…",
        updated=config.get("last_updated", "Never"),
        refresh=config.get("refresh_interval", 30),
        name_version=name_change_version,
        poll_interval=config.get("cache_ttl", 15),
        screensaver_enabled=screensaver_enabled,
        screensaver_timeout=screensaver_timeout,
        idle_for=idle_for_effective,
        heartbeat_interval=HEARTBEAT_INTERVAL,
        pos=pos,
    )

@app.route("/api/name-version")
def name_version_api():
    get_podium_data()  # refreshes cache if TTL expired
    return {"version": name_change_version, "updated": config.get("last_updated", "Never")}


@app.route("/api/display-heartbeat", methods=["POST"])
def display_heartbeat():
    data = request.get_json(silent=True) or {}
    pos = int(data.get("pos") or 0)
    if pos not in (1, 2, 3):
        return {"ok": False, "error": "invalid position"}, 400
    update_display_status(pos, data)
    return {"ok": True}


@app.route("/api/admin/status")
def admin_status_api():
    data, _ = get_podium_data()
    summary = summarize_display_status()
    rows = [
        {
            "pos": pos,
            **summary[pos],
        }
        for pos in sorted(summary)
    ]
    return {"statuses": rows}


@app.route("/api/admin/wifi-status")
def admin_wifi_status_api():
    return {"results": fetch_wifi_status()}


def schedule_restart() -> None:
    """Re-exec the current process after a short delay."""
    def _restart():
        time.sleep(0.5)
        os.execl(sys.executable, sys.executable, *sys.argv)

    Thread(target=_restart, daemon=True).start()


@app.route("/api/admin/restart", methods=["POST"])
def admin_restart_api():
    schedule_restart()
    return {"ok": True, "message": "restarting"}

# --------------------------------------------------
# Main
# --------------------------------------------------

if __name__ == "__main__":
    load_config()
    print("🏆 PODIUM DISPLAY SERVER – STABLE FINAL")
    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=5001, debug=False)


