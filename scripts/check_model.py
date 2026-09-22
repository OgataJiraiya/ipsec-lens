"""Regenerate separately and compare to the committed digest; never replace production."""
import hashlib
from pathlib import Path
import tempfile
from backend.core.config import ROOT
from training.train import train


def main():
    expected = (ROOT / "models/classifier.sha256").read_text().strip()
    with tempfile.TemporaryDirectory(prefix="ipseclens-model-check-") as directory:
        output = Path(directory)
        train(output)
        actual = hashlib.sha256((output / "classifier.json").read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit("Deterministic model check failed: regenerated digest differs from committed digest")
        production = ROOT / "models/classifier.json"
        if not production.is_file():
            raise SystemExit("Production artifact missing: run make train with pinned dependencies first")
        if hashlib.sha256(production.read_bytes()).hexdigest() != expected:
            raise SystemExit("Production model differs from committed digest")
    print("Deterministic model and production integrity: PASS " + expected)


if __name__ == "__main__":
    main()
