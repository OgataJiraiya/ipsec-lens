import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("IPSECLENS_DATA_DIR", str(ROOT / "runtime"))).resolve()
MAX_UPLOAD = int(os.getenv("IPSECLENS_MAX_UPLOAD", 256 * 1024 * 1024))
MAX_PACKETS = int(os.getenv("IPSECLENS_MAX_PACKETS", 1_000_000))
MAX_FLOWS = int(os.getenv("IPSECLENS_MAX_FLOWS", 4096))
MAX_PACKET_SIZE = 262144
MAX_IKE_MESSAGES = 4096
MAX_TELEMETRY = 2 * 1024 * 1024
ABSTENTION = float(os.getenv("IPSECLENS_ABSTENTION", "0.60"))
if not 0 <= ABSTENTION <= 1:
    raise ValueError("Invalid abstention threshold")
