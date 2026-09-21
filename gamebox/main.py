"""Convenience entrypoint mirroring `python -m gamebox`."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
