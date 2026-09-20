#!/usr/bin/env python3
"""Compatibility wrapper. WebHawk is the current tool."""
from webhawk import main
if __name__ == "__main__":
    raise SystemExit(main())
