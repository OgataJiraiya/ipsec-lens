import hashlib
import pytest
from backend.ml.features import extract, FEATURES, bidirectional_features
from backend.ml.classifier import predict, load_model
from training.generate_manifest import manifest, samples
from training.train import train


def test_features():
    f=extract([(0,100),(1,200),(2,300)])
    assert list(f)==FEATURES and f["mean_size"]==200 and f["duration"]==2
    assert sum(f[k] for k in ("size_bin_0","size_bin_1","size_bin_2","size_bin_3"))==1


def test_empty_features():
    assert all(v==0 for v in extract([]).values())


def test_bidirectional_features():
    f=bidirectional_features([(0,100),(1,200)],[(.5,300)])
    assert f["direction_ratio"]==2/3 and f["request_response_asymmetry"]==1/3


def test_split_integrity():
    rows=manifest()
    groups={s:{r["configuration"] for r in rows if r["split"]==s} for s in ("train","validation","test")}
    assert groups["train"].isdisjoint(groups["validation"]|groups["test"])
    assert groups["validation"].isdisjoint(groups["test"])
    assert len({r["session_id"] for r in rows})==len(rows)
    assert not {"label","seed","configuration","session_id"} & set(FEATURES)


def test_prediction_confidence():
    p=predict("test",samples({"seed":1,"label":"VOIP"}))
    assert p.predicted_class=="VOIP" and 0<=p.confidence<=1
    assert sum(p.probabilities.values())==pytest.approx(1)


def test_abstention(monkeypatch):
    assert predict("x",[(0,100)]).predicted_class=="UNKNOWN"
    import numpy as np
    monkeypatch.setattr("backend.ml.classifier.probabilities", lambda model, row: np.ones(7) / 7)
    p=predict("x",samples({"seed":2,"label":"WEB"}),threshold=.60)
    assert p.predicted_class=="UNKNOWN" and p.confidence < .60


def test_model_hash():
    from backend.ml.classifier import MODEL_PATH
    assert load_model()["model_sha256"]==hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()


def test_training_reproducible(tmp_path):
    a=train(tmp_path/"a")
    b=train(tmp_path/"b")
    assert (tmp_path/"a/classifier.json").read_bytes()==(tmp_path/"b/classifier.json").read_bytes()
    assert a["metrics"]==b["metrics"]


def test_synthetic_metrics():
    model=load_model()
    assert model["metrics"]["test"]["samples"]==168
    assert "SYNTHETIC" in model["metadata"]["training_source"]
