"""Optional interactive PyPI update check for the command-line application."""
from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import sys
import sysconfig
import time
import urllib.request
from pathlib import Path
from typing import Any


_PYPI_JSON_URL = "https://pypi.org/pypi/daclhound/json"
_CHECK_INTERVAL = 24 * 60 * 60


def _cache_file() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"])
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "daclhound" / "update-check.json"


def _read_cache() -> dict[str, Any]:
    try:
        value = json.loads(_cache_file().read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write_cache(value: dict[str, Any]) -> None:
    path = _cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    except OSError:
        # Update checking must never prevent the main CLI from starting.
        pass


def _is_newer(candidate: str, installed: str) -> bool:
    """Compare the numeric release versions used by DACLhound on PyPI."""
    pattern = r"^\s*(\d+(?:\.\d+)*)\s*$"
    candidate_match = re.fullmatch(pattern, candidate)
    installed_match = re.fullmatch(pattern, installed)
    if not candidate_match or not installed_match:
        return False
    candidate_parts = tuple(int(part) for part in candidate_match.group(1).split("."))
    installed_parts = tuple(int(part) for part in installed_match.group(1).split("."))
    width = max(len(candidate_parts), len(installed_parts))
    return candidate_parts + (0,) * (width - len(candidate_parts)) > (
        installed_parts + (0,) * (width - len(installed_parts))
    )


def _latest_version(cache: dict[str, Any], now: float) -> str | None:
    cached_version = cache.get("latest_version")
    checked_at = cache.get("checked_at")
    if (isinstance(cached_version, str) and isinstance(checked_at, (int, float))
            and 0 <= now - checked_at < _CHECK_INTERVAL):
        return cached_version

    request = urllib.request.Request(
        _PYPI_JSON_URL,
        headers={"User-Agent": "DACLhound update check"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            payload = json.load(response)
        version = payload.get("info", {}).get("version") if isinstance(payload, dict) else None
        if isinstance(version, str):
            cache.update(checked_at=now, latest_version=version)
            _write_cache(cache)
            return version
    except (OSError, ValueError, TypeError):
        pass
    if isinstance(cached_version, str):
        # Avoid repeating a failed network request on every interactive launch.
        cache["checked_at"] = now
        _write_cache(cache)
    return cached_version if isinstance(cached_version, str) else None


def _read_key() -> str:
    """Read one arrow/enter key without requiring an extra package."""
    if os.name == "nt":
        import msvcrt

        key = msvcrt.getwch()
        if key in ("\x00", "\xe0"):
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
        if key in ("\r", "\n"):
            return "enter"
        if key == "\x1b":
            return "escape"
        return ""

    import termios
    import tty

    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        key = os.read(fd, 1).decode("utf-8", errors="ignore")
        if key in ("\r", "\n"):
            return "enter"
        if key in ("\x03", "\x04"):
            return "escape"
        if key != "\x1b":
            return ""
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            return "escape"
        if os.read(fd, 1) != b"[":
            return ""
        return {b"A": "up", b"B": "down"}.get(os.read(fd, 1), "")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def _choose_action(version: str, current: str) -> str:
    choices = ("Update now", "Skip", "Skip until next version")
    selected = 0
    print(f"A new DACLhound version is available: {version} (installed: {current})")
    print("Use the arrow keys and press Enter:")

    def render() -> None:
        for index, label in enumerate(choices):
            marker = ">" if index == selected else " "
            sys.stdout.write(f"\r\x1b[2K{marker} {label}")
            if index < len(choices) - 1:
                sys.stdout.write("\n")
        sys.stdout.flush()

    render()
    while True:
        key = _read_key()
        if key == "up":
            selected = (selected - 1) % len(choices)
        elif key == "down":
            selected = (selected + 1) % len(choices)
        elif key == "escape":
            selected = 1
            break
        elif key == "enter":
            break
        else:
            continue
        sys.stdout.write(f"\x1b[{len(choices) - 1}A")
        render()
    print()
    return ("install", "skip", "skip_until_next_version")[selected]


def _install_command() -> list[str]:
    prefix = str(Path(sys.prefix).resolve()).replace("\\", "/").casefold()
    if "/pipx/venvs/" in prefix:
        pipx = shutil.which("pipx")
        if pipx:
            return [pipx, "upgrade", "DACLhound"]
    if "/uv/tools/" in prefix:
        uv = shutil.which("uv")
        if uv:
            return [uv, "tool", "upgrade", "DACLhound"]
    return [sys.executable, "-m", "pip", "install", "--upgrade", "DACLhound"]


def _running_from_installed_package() -> bool:
    module_path = Path(__file__).resolve()
    for key in ("purelib", "platlib"):
        try:
            if module_path.is_relative_to(Path(sysconfig.get_path(key)).resolve()):
                return True
        except (OSError, ValueError):
            continue
    return False


def maybe_prompt_for_update(current_version: str) -> None:
    """Prompt interactively when PyPI has a newer stable DACLhound release."""
    if (os.environ.get("DACLHOUND_NO_UPDATE_CHECK", "").casefold() in {"1", "true", "yes"}
            or not sys.stdin.isatty() or not sys.stdout.isatty()
            or not _running_from_installed_package()):
        return

    now = time.time()
    cache = _read_cache()
    latest = _latest_version(cache, now)
    if not latest or not _is_newer(latest, current_version):
        return

    remind_until = cache.get("remind_until", 0)
    if (cache.get("remind_for_version") == latest and isinstance(remind_until, (int, float))
            and remind_until > now):
        return
    if cache.get("skip_until_version") == latest:
        return

    try:
        action = _choose_action(latest, current_version)
    except (OSError, ValueError):
        return
    if action == "skip":
        return
    if action == "skip_until_next_version":
        cache.update(skip_until_version=latest, remind_for_version=None, remind_until=0)
        _write_cache(cache)
        return

    command = _install_command()
    print("Updating DACLhound...")
    try:
        result = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Could not start the updater: {exc}", file=sys.stderr)
        return
    if result.returncode == 0:
        cache.update(skip_until_version=None, remind_for_version=None, remind_until=0)
        _write_cache(cache)
        print(f"DACLhound {latest} installed.")
        print("Restarting DACLhound with the updated version...")
        try:
            os.execv(sys.executable, [sys.executable, "-m", "daclhound_cli", *sys.argv[1:]])
        except OSError as exc:
            print(f"Restart failed ({exc}); run DACLhound again to use the new version.",
                  file=sys.stderr)
    else:
        print(f"Update failed (exit code {result.returncode}); continuing with {current_version}.",
              file=sys.stderr)
