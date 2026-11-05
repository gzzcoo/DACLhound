#!/usr/bin/env python3
"""Compatibility launcher for the DACLhound graph server."""
from daclhound.server import DatasetStore, main, make_handler, run_server

__all__ = ["DatasetStore", "make_handler", "run_server", "main"]

if __name__ == "__main__":
    raise SystemExit(main())
