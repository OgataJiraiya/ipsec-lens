"""Remove only analyses explicitly labelled as generated demos; preserve user analyses/captures."""
import json
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import delete
from backend.database.store import Store, Run
from backend.core.config import DATA_DIR
from backend.schemas.models import Analysis


def main():
    fixture_root = Path(__file__).resolve().parents[1] / "demo"
    known_hashes = {json.loads(p.read_text())["capture_sha256"] for p in fixture_root.glob("*/manifest.json")}
    store = Store(DATA_DIR)
    with Session(store.engine) as session, session.begin():
        from sqlalchemy import select
        rows = list(session.scalars(select(Run)))
        for row in rows:
            run = Analysis.model_validate_json(row.document)
            if run.label.startswith("SYNTHETIC FIXTURE · ") and run.capture_sha256 in known_hashes:
                session.execute(delete(Run).where(Run.id == row.id))
    folder = DATA_DIR / "demo-reports"
    if folder.exists():
        for name in ("strong", "weak", "replay", "partial", "ipv6"):
            for suffix in (".json", "-executive.html", "-technical.html"):
                (folder / (name + suffix)).unlink(missing_ok=True)
        (folder / "results.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
