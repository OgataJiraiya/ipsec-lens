import numpy as np
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix


def evaluate(model, x, y):
    pred, probs = model.predict(x), model.predict_proba(x)
    classes = list(model.classes_)
    onehot = np.array([[int(v == c) for c in classes] for v in y])
    confidence = probs.max(axis=1)
    correct = np.asarray(pred == y)
    ece = 0.0
    for lo in np.arange(0, 1, .1):
        mask = (confidence > lo) & (confidence <= lo + .1 + 1e-12)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    return {"accuracy": accuracy_score(y, pred), "macro_f1": f1_score(y, pred, average="macro"),
            "weighted_f1": f1_score(y, pred, average="weighted"),
            "per_class": classification_report(y, pred, output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(y, pred, labels=classes).tolist(),
            "classes": classes, "multiclass_brier": float(np.mean(np.sum((probs - onehot)**2, axis=1))),
            "expected_calibration_error_10_bins": float(ece), "samples": len(y)}


if __name__ == "__main__":
    from pathlib import Path
    print(Path("models/metrics.json").read_text())
