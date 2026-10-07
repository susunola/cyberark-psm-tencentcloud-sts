"""Validate a configuration file without contacting Tencent Cloud."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from configuration import load_settings
from federation import FederationError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("config", type=Path)
args = parser.parse_args()
try:
    settings = load_settings(args.config)
except (OSError, ValueError, FederationError):
    parser.exit(
        2, "Configuration invalid. Check required fields, caller bindings, role ARN and destination.\n"
    )
print(f"Configuration valid: {len(settings['profiles'])} profile(s). No cloud calls performed.")
