"""Lifecycle management for the local graph viewer process."""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


def _cli_script_path() -> Path:
    """Return the compatibility launcher used to start or identify the CLI daemon."""
    return Path(__file__).resolve().parent.parent / "daclhound_cli.py"


def _graph_pid_file(bind: str, port: int) -> Path:
    safe_bind = re.sub(r"[^A-Za-z0-9_.-]+", "_", bind)
    runtime_base = os.environ.get("XDG_RUNTIME_DIR") or str(Path.home() / ".local" / "state")
    runtime = Path(runtime_base).expanduser() / "daclhound"
    return runtime / f"graph-{safe_bind}-{port}.pid"


def _graph_daemon_matches(pid: int) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return False
    return (str(_cli_script_path()).encode() in command
            and b"graph" in command and b"--_daemon-child" in command)


def _read_graph_pid(path: Path) -> int | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = int(value["pid"])
        return pid if pid > 1 else None
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _start_graph_server(bind: str, port: int, input_path: str | None, verbose: bool) -> int:
    pid_file = _graph_pid_file(bind, port)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    previous_pid = _read_graph_pid(pid_file)
    if previous_pid and _graph_daemon_matches(previous_pid):
        print(f"[+] DACLhound graph already running at http://{bind}:{port}/ (PID {previous_pid})")
        return 0
    pid_file.unlink(missing_ok=True)
    command = [sys.executable, str(_cli_script_path()), "graph", "run",
               "--bind", bind, "--port", str(port), "--_daemon-child",
               "--_pid-file", str(pid_file)]
    if input_path:
        command.extend(["--input", input_path])
    if verbose:
        command.append("--verbose")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    deadline = time.monotonic() + 5.0
    ready = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection((bind, port), timeout=0.15):
                ready = True
                break
        except OSError:
            time.sleep(0.1)
    if not ready:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
        raise RuntimeError(f"Could not start the graph server on {bind}:{port}; check whether the port is already in use")
    pid_file.write_text(json.dumps({"pid": process.pid, "bind": bind, "port": port}) + "\n", encoding="utf-8")
    print(f"[+] DACLhound graph started at http://{bind}:{port}/ (PID {process.pid})")
    print("[+] Stop it with: DACLhound.py graph stop")
    return 0


def _stop_graph_server(bind: str, port: int) -> int:
    pid_file = _graph_pid_file(bind, port)
    pid = _read_graph_pid(pid_file)
    if not pid or not _graph_daemon_matches(pid):
        pid_file.unlink(missing_ok=True)
        print(f"[i] No DACLhound background server found for {bind}:{port}")
        return 0
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _graph_daemon_matches(pid):
            pid_file.unlink(missing_ok=True)
            print(f"[+] DACLhound graph stopped (PID {pid})")
            return 0
        time.sleep(0.1)
    raise RuntimeError(f"DACLhound graph PID {pid} did not stop within 5 seconds")
