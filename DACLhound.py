#!/usr/bin/env python3
"""Compatibility launcher for DACLhound."""
from daclhound_cli import entrypoint

if __name__ == "__main__":
    raise SystemExit(entrypoint())
