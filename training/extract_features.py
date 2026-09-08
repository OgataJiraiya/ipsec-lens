from backend.ml.features import extract, FEATURES
from training.generate_manifest import manifest, samples
import pandas as pd


def dataset():
    return pd.DataFrame([{**row, **extract(samples(row))} for row in manifest()])


if __name__ == "__main__":
    from pathlib import Path
    Path("datasets/generated").mkdir(parents=True, exist_ok=True)
    dataset().to_csv("datasets/generated/features.csv", index=False)
    print(f"Extracted {len(FEATURES)} metadata features per session.")
