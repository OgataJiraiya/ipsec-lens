"""Validation-only selection; final test evaluated once after selection. JSON, never pickle."""
import hashlib
import json
from pathlib import Path
import sklearn
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from backend.ml.features import FEATURES
from training.generate_manifest import SEED, write
from training.extract_features import dataset
from training.evaluate import evaluate


def tree_json(tree):
    return {"left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
            "feature": tree.feature.tolist(), "threshold": tree.threshold.tolist(),
            "value": tree.value[:, 0, :].tolist()}


def export(model, name):
    base = {"kind": name, "classes": list(model.classes_), "features": FEATURES}
    if name == "RandomForest":
        base["trees"] = [tree_json(t.tree_) for t in model.estimators_]
    elif name == "LogisticRegression":
        scaler, classifier = model.steps[0][1], model.steps[1][1]
        base.update(mean=scaler.mean_.tolist(), scale=scaler.scale_.tolist(),
                    coef=classifier.coef_.tolist(), intercept=classifier.intercept_.tolist())
    else:
        base.update(priors=model.init_.class_prior_.tolist(), learning_rate=model.learning_rate,
                    stages=[[tree_json(t.tree_) for t in stage] for stage in model.estimators_])
    return base


def train(output=Path("models")):
    manifest_hash = write()
    data = dataset()
    data_hash = hashlib.sha256(data.to_csv(index=False, float_format="%.12g").encode()).hexdigest()
    subsets = {s: data[data.split == s] for s in ("train", "validation", "test")}
    x = {s: frame[FEATURES].to_numpy() for s, frame in subsets.items()}
    y = {s: frame.label.to_numpy() for s, frame in subsets.items()}
    candidates = {
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=9, min_samples_leaf=2,
                                               random_state=SEED, n_jobs=1),
        "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=60, max_depth=2, random_state=SEED),
    }
    validation = {}
    for name, model in candidates.items():
        model.fit(x["train"], y["train"])
        validation[name] = evaluate(model, x["validation"], y["validation"])
    best = max(candidates, key=lambda n: validation[n]["macro_f1"])
    chosen = candidates[best]
    artifact = export(chosen, best)
    artifact["metadata"] = {"seed": SEED, "training_source": "SYNTHETIC FIXTURE metadata profiles",
        "dataset_sha256": data_hash, "manifest_sha256": manifest_hash, "sklearn_version": sklearn.__version__,
        "split_method": "Disjoint configuration groups; one feature row per independent session",
        "split_sizes": {s: len(f) for s, f in subsets.items()},
        "selection": "Highest validation macro F1, stable candidate-order tie break",
        "calibration": "Uncalibrated probabilities; ECE and Brier reported on synthetic test only",
        "abstention_threshold": .60, "minimum_packets": 20,
        "non_claims": ["No decryption", "No application/vendor attribution", "No real-world accuracy claim"]}
    metrics = {"selected_model": best, "validation": validation, "test": evaluate(chosen, x["test"], y["test"])}
    artifact["metrics"] = metrics
    output.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(artifact, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    (output / "classifier.json").write_bytes(raw)
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    (output / "classifier.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    # Verify portable inference equals the selected sklearn classifier.
    from backend.ml.classifier import probabilities
    for row, expected in zip(x["test"][:20], chosen.predict_proba(x["test"][:20]), strict=True):
        assert np.allclose(probabilities(artifact, row), expected, atol=1e-6)
    print(json.dumps({"model": best, "test": metrics["test"]["macro_f1"],
                      "model_sha256": hashlib.sha256(raw).hexdigest()}))
    return artifact


if __name__ == "__main__":
    train()
