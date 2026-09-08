"""Portable trusted built-in JSON inference; no dynamic imports or unsafe deserialization."""
import hashlib
import json
import math
from functools import lru_cache
import numpy as np
from backend.core.config import ROOT, ABSTENTION
from backend.core.security_policy import MIN_FLOW_PACKETS
from backend.ml.features import FEATURES, extract
from backend.schemas.models import Prediction

MODEL_PATH = ROOT / "models/classifier.json"


def leaf(tree, row):
    i = 0
    for _ in range(64):
        if tree["left"][i] == -1:
            return np.array(tree["value"][i], dtype=float)
        i = tree["left"][i] if row[tree["feature"][i]] <= tree["threshold"][i] else tree["right"][i]
    raise ValueError("Model tree depth invalid")


def probabilities(model, row):
    row = np.asarray(row, dtype=np.float32)
    if model["kind"] == "RandomForest":
        values = [leaf(tree, row) for tree in model["trees"]]
        result = np.mean([v / v.sum() for v in values], axis=0)
    elif model["kind"] == "LogisticRegression":
        normalized = (row - np.array(model["mean"])) / np.array(model["scale"])
        logits = np.array(model["coef"]) @ normalized + model["intercept"]
        result = np.exp(logits - logits.max())
        result /= result.sum()
    else:
        logits = np.log(model["priors"])
        for stage in model["stages"]:
            logits += model["learning_rate"] * np.array([leaf(t, row)[0] for t in stage])
        result = np.exp(logits - logits.max())
        result /= result.sum()
    return result


@lru_cache(maxsize=1)
def load_model():
    if not MODEL_PATH.is_file():
        return None
    if MODEL_PATH.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Built-in model exceeds limit")
    raw = MODEL_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != MODEL_PATH.with_suffix(".sha256").read_text().strip():
        raise ValueError("Built-in model integrity check failed")
    model = json.loads(raw)
    if model["features"] != FEATURES or model["kind"] not in ("RandomForest", "LogisticRegression", "GradientBoosting"):
        raise ValueError("Built-in model schema mismatch")
    model["model_sha256"] = digest
    return model


def model_info():
    model = load_model()
    if model is None:
        return {"status": "UNAVAILABLE", "reason": "Run make train to build the trusted synthetic classifier",
                "features": FEATURES, "abstention_threshold": ABSTENTION}
    return {"status": "AVAILABLE", "kind": model["kind"], "classes": model["classes"], "features": FEATURES,
            "metadata": model["metadata"], "metrics": model["metrics"], "model_sha256": model["model_sha256"],
            "abstention_threshold": ABSTENTION}


def predict(flow_id: str, samples: list[tuple[float, int]], threshold=ABSTENTION) -> Prediction:
    features = extract(samples)
    model = load_model()
    limitations = ["Encrypted payload was not decrypted. Classification is based on flow metadata.",
                   "Trained on synthetic profiles only; confidence is not calibrated real-world accuracy.",
                   "Directional SPI group may multiplex many applications; first 2048 packets used.",
                   "No WhatsApp identification, traffic authenticity or attack probability is inferred."]
    if model is None or len(samples) < MIN_FLOW_PACKETS:
        return Prediction(flow_id=flow_id, predicted_class="UNKNOWN", confidence=0,
                          probabilities={}, features=features, limitations=limitations + ["Model unavailable or insufficient packets."])
    probs = probabilities(model, [features[k] for k in FEATURES])
    idx = int(np.argmax(probs))
    confidence = float(probs[idx])
    if not math.isfinite(confidence):
        raise ValueError("Non-finite model output")
    return Prediction(flow_id=flow_id, predicted_class=model["classes"][idx] if confidence >= threshold else "UNKNOWN",
                      confidence=confidence, probabilities=dict(zip(model["classes"], probs.tolist(), strict=True)),
                      features=features, limitations=limitations + (["Confidence below abstention threshold."] if confidence < threshold else []))
