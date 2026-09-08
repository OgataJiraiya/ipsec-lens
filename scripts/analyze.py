import argparse
import uuid
from pathlib import Path
from backend.services.analysis import build_analysis
from backend.telemetry.importer import Telemetry

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--telemetry", type=Path)
    parser.add_argument("--policy", choices=["MODERN", "COMPATIBILITY", "STRICT"], default="MODERN")
    args = parser.parse_args()
    telemetry = Telemetry.model_validate_json(args.telemetry.read_bytes()) if args.telemetry else None
    print(build_analysis(args.capture, uuid.uuid4().hex, args.capture.name, "", args.policy,
                         telemetry=telemetry).model_dump_json(indent=2))
