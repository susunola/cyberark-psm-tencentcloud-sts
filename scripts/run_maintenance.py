"""Run from an authorized scheduler wrapper which obtains fresh credentials each run."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from configuration import load_settings
from pam.cloud import Cloud
from pam.files import read_json
from pam.maintenance import run
from pam.vault import Vault

FAILURE_MESSAGE = (
    "Maintenance stopped. Inspect protected journals and reconcile uncertain outcomes "
    "before retry; no secrets are emitted.\n"
)


def execute(args: argparse.Namespace) -> list[dict[str, str]]:
    cloud = Cloud(os.environ["TENCENTCLOUD_SECRET_ID"], os.environ["TENCENTCLOUD_SECRET_KEY"])
    vault = Vault(
        os.environ["PVWA_API_URL"],
        os.environ["PVWA_TOKEN"],
        ca=os.environ.get("PVWA_CA_BUNDLE") or True,
    )
    return run(read_json(args.jobs), load_settings(args.settings), args.state_dir, cloud, vault)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", required=True)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply:
        print(json.dumps({"status": "no-write", "next": "Review jobs and supply --apply to run maintenance"}))
        return
    try:
        result: Any = execute(args)
    except Exception:  # noqa: BLE001 - never emit secrets, journals or raw API errors
        parser.exit(2, FAILURE_MESSAGE)
    print(json.dumps({"results": result}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
