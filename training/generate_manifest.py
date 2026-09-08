"""Synthetic metadata sessions, not real applications or encrypted deployment captures."""
import hashlib
import json
from pathlib import Path
import numpy as np

LABELS = ["VOIP", "MESSAGING", "EMAIL", "WEB", "ICMP", "VIDEO", "OTHER"]
SEED = 26160


def manifest():
    return [{"session_id": f"cfg{config:02}-{label.lower()}-{run:02}", "configuration": f"cfg{config:02}",
             "label": label, "seed": SEED + config * 10000 + label_index * 100 + run,
             "split": "train" if config < 6 else "validation" if config < 8 else "test",
             "source": "SYNTHETIC FIXTURE"}
            for config in range(10) for label_index, label in enumerate(LABELS) for run in range(12)]


def samples(row):
    rng = np.random.default_rng(row["seed"])
    label = row["label"]
    n = int(rng.integers(90, 260))
    if label == "VOIP":
        sizes, gaps = rng.normal(220, 18, n), rng.normal(.02, .002, n)
    elif label == "MESSAGING":
        sizes, gaps = rng.normal(170, 65, n), rng.exponential(.045, n)
        gaps[::7] += rng.uniform(.3, 1.8, len(gaps[::7]))
    elif label == "EMAIL":
        sizes, gaps = rng.normal(850, 290, n), rng.exponential(.08, n)
        gaps[::20] += .8
    elif label == "WEB":
        sizes = rng.choice([140, 550, 1400], n, p=[.25, .15, .6]) + rng.normal(0, 35, n)
        gaps = rng.exponential(.012, n)
        gaps[::25] += .3
    elif label == "ICMP":
        sizes, gaps = rng.normal(130, 4, n), rng.normal(1, .02, n)
    elif label == "VIDEO":
        sizes, gaps = rng.normal(1400, 60, n), rng.exponential(.002, n)
    else:
        sizes, gaps = rng.uniform(100, 1500, n), rng.exponential(.25, n)
    # Session-specific path overhead and timing jitter, without configuration ID as a model feature.
    sizes += rng.uniform(-20, 40)
    gaps *= rng.uniform(.7, 1.4)
    times = np.cumsum(np.maximum(gaps, .00001))
    return [(float(t), int(np.clip(s, 64, 1500))) for t, s in zip(times, sizes, strict=True)]


def write(root=Path("datasets")):
    rows = manifest()
    path = root / "manifests/synthetic.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    print(write())
