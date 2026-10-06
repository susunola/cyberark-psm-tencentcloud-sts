"""Backward-compatible launcher. Prefer `python -m psm_tc_bridge`."""

from psm_tc_bridge.app import create_app, main

if __name__ == '__main__':
    main()
