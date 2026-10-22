"""Serve the DACL graph viewer and keep uploaded datasets in process memory."""
from __future__ import annotations

import argparse
from importlib.resources import files
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

VIEWER = files("daclhound_assets").joinpath("viewer.html")
MAX_BODY = 64 * 1024 * 1024


class DatasetStore:
    """Thread-safe, process-local storage for uploaded graph datasets."""

    def __init__(self, initial_json: str | None = None) -> None:
        self._lock = threading.Lock()
        self._next_id = 1
        self._datasets: list[dict] = []
        if initial_json:
            path = Path(initial_json).expanduser().resolve()
            self.add(path.name, json.loads(path.read_text(encoding="utf-8")))

    def add(self, name: str, data: object) -> dict:
        if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or not isinstance(data.get("edges"), list):
            raise ValueError("Expected a DACL graph JSON object with nodes and edges arrays")
        with self._lock:
            key = str(self._next_id)
            self._next_id += 1
            item = {"key": key, "name": name or "daclgraph.json", "data": data}
            self._datasets.append(item)
            return item

    def list(self) -> list[dict]:
        with self._lock:
            return list(self._datasets)

    def remove(self, key: str) -> bool:
        with self._lock:
            remaining = [item for item in self._datasets if item["key"] != key]
            if len(remaining) == len(self._datasets):
                return False
            self._datasets = remaining
            return True


def make_handler(store: DatasetStore, log_requests: bool = False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DACLGraph/1.0"

        def log_message(self, fmt: str, *args) -> None:
            if log_requests:
                print(f"[{self.log_date_time_string()}] {fmt % args}")

        def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status: int, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_bytes(status, body, "application/json; charset=utf-8")

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/datasets":
                self.send_json(200, store.list())
                return
            if path in ("/", "/daclgraph_viewer.html"):
                try:
                    self.send_bytes(200, VIEWER.read_bytes(), "text/html; charset=utf-8")
                except OSError as exc:
                    self.send_json(500, {"error": str(exc)})
                return
            self.send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path != "/api/datasets":
                self.send_json(404, {"error": "Not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self.send_json(400, {"error": "Request body must be between 1 byte and 64 MiB"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(400, {"error": "Invalid JSON request body"})
                return
            if not isinstance(payload, dict):
                self.send_json(400, {"error": "Expected an object containing name and data"})
                return
            try:
                item = store.add(str(payload.get("name") or "daclgraph.json"), payload.get("data"))
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            self.send_json(201, item)

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            prefix = "/api/datasets/"
            if not path.startswith(prefix):
                self.send_json(404, {"error": "Not found"})
                return
            key = unquote(path[len(prefix):])
            if not store.remove(key):
                self.send_json(404, {"error": "Dataset not found"})
                return
            self.send_json(200, {"removed": key})

    return Handler


def run_server(host: str = "127.0.0.1", port: int = 8765, initial_json: str | None = None, log_requests: bool = False) -> None:
    store = DatasetStore(initial_json)
    server = ThreadingHTTPServer((host, port), make_handler(store, log_requests))
    print(f"[+] DACLhound server listening at http://{host}:{port}/")
    print("[+] Uploaded datasets are kept in memory until this process exits")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping DACLhound server")
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the interactive DACL graph viewer with in-memory datasets.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    parser.add_argument("--initial-json", help="Load one graph JSON into the in-memory session on startup")
    parser.add_argument("--verbose", action="store_true", help="Log each HTTP request")
    args = parser.parse_args()
    run_server(args.host, args.port, args.initial_json, args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
