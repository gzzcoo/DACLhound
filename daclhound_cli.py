#!/usr/bin/env python3
"""Compatibility module and launcher for the modular DACLhound package."""
from daclhound import __version__
from daclhound.cli import entrypoint, main

__all__ = ["__version__", "entrypoint", "main"]

if __name__ == "__main__":
    raise SystemExit(entrypoint())
