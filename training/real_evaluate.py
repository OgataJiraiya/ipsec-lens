"""Predeclared preliminary real-testbed evaluation. Never selects against held-out test.
The production synthetic model is preserved. Experimental model artifacts stay in runtime/.
"""
import hashlib
from typing import Any
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score
from backend.ml.features import FEATURES, extract
from backend.ml.classifier import load_model, probabilities
from backend.protocol.analyzer import analyze_capture
from training.extract_features import dataset as synthetic_dataset
from training.evaluate import evaluate
from training.train import export
from training.generate_manifest import SEED

ROOT=Path(__file__).resolve().parents[1]


def assert_split(rows):
    seen: dict[str, str] = {}
    hashes = set()
    sessions = set()
    for row in rows:
        if row["session_id"] in sessions or row["capture_sha256"] in hashes:
            raise ValueError("Repeated session/capture identity")
        sessions.add(row["session_id"])
        hashes.add(row["capture_sha256"])
        if row["group_id"] in seen and seen[row["group_id"]] != row["split"]:
            raise ValueError("Tunnel group crosses dataset splits")
        seen[row["group_id"]] = row["split"]


def build_rows():
    rows=[]
    for path in sorted((ROOT/"runtime/live").glob("*-g*/sessions.json")):
        for row in json.loads(path.read_text()):
            capture=ROOT/row["capture"]
            with capture.open("rb") as stream:
                digest=hashlib.file_digest(stream,"sha256").hexdigest()
            if digest!=row["capture_sha256"]:
                raise ValueError("Real capture identity mismatch")
            summary,flows,_,_,warnings=analyze_capture(capture)
            if warnings or not summary.counts.get("ESP"):
                raise ValueError("Incomplete or non-ESP session")
            # One predetermined representative direction per session. Other directions never cross splits.
            dominant=max(flows,key=lambda flow:flow.byte_count)
            rows.append({**row,**extract(dominant.samples),
                         "direction_rule":"largest observed byte volume; first 2048 packets",
                         "observed_esp_packets":summary.counts["ESP"]})
    if len(rows)!=120:
        raise ValueError("Expected the complete predeclared 120-session dataset")
    assert_split(rows)
    return rows


class Portable:
    def __init__(self,model):
        self.model=model
        self.classes_=np.asarray(model["classes"])
    def predict_proba(self,x):
        return np.asarray([probabilities(self.model,row) for row in x])
    def predict(self,x):
        return self.classes_[self.predict_proba(x).argmax(axis=1)]


def choose_threshold(model,x,y):
    probs=model.predict_proba(x)
    confidence=probs.max(axis=1)
    predictions=model.classes_[probs.argmax(axis=1)]
    options: list[dict[str, Any]]=[]
    for threshold in (.4,.5,.6,.7,.8,.9):
        keep=confidence>=threshold
        options.append({"threshold":threshold,"coverage":float(keep.mean()),
                        "selective_accuracy":float((predictions[keep]==y[keep]).mean()) if keep.any() else None})
    valid=[r for r in options if r["selective_accuracy"] is not None and r["selective_accuracy"]>=.8 and r["coverage"]>=.25]
    chosen=max(valid,key=lambda r:(r["coverage"],r["threshold"]))["threshold"] if valid else .6
    return chosen,options


def abstention(model,x,y,threshold):
    probs=model.predict_proba(x)
    confidence=probs.max(axis=1)
    keep=confidence>=threshold
    pred=model.classes_[probs.argmax(axis=1)]
    out=np.where(keep,pred,"UNKNOWN")
    return {"threshold":threshold,"coverage":float(keep.mean()),"abstained":int((~keep).sum()),
            "selective_accuracy":accuracy_score(y[keep],pred[keep]) if keep.any() else None,
            "accuracy_counting_abstention_as_error":accuracy_score(y,out),
            "macro_f1_including_unknown":f1_score(y,out,average="macro",zero_division=0)}


def fit_select(train,validation):
    candidates={
        "RandomForest":RandomForestClassifier(n_estimators=100,max_depth=9,min_samples_leaf=2,random_state=SEED,n_jobs=1),
        "LogisticRegression":make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,random_state=SEED)),
        "GradientBoosting":GradientBoostingClassifier(n_estimators=60,max_depth=2,random_state=SEED)}
    metrics={}
    x,y=train[FEATURES].to_numpy(),train.label.to_numpy()
    vx,vy=validation[FEATURES].to_numpy(),validation.label.to_numpy()
    for name,model in candidates.items():
        model.fit(x,y)
        metrics[name]=evaluate(model,vx,vy)
    best=max(candidates,key=lambda name:metrics[name]["macro_f1"])
    return candidates[best],best,metrics


def experiment(name,train,validation,test):
    model,best,val=fit_select(train,validation)
    threshold,options=choose_threshold(model,validation[FEATURES].to_numpy(),validation.label.to_numpy())
    # Test access occurs only after model AND threshold selection. No feedback loop from test.
    result={"selected_model":best,"validation":val,"threshold_selection":options,
            "test":evaluate(model,test[FEATURES].to_numpy(),test.label.to_numpy()),
            "abstention":abstention(model,test[FEATURES].to_numpy(),test.label.to_numpy(),threshold)}
    path=ROOT/"runtime/real_models"
    path.mkdir(parents=True,exist_ok=True)
    (path/(name+".json")).write_text(json.dumps(export(model,best),sort_keys=True)+"\n")
    return result


def main():
    rows=build_rows()
    manifest_path=ROOT/"datasets/manifests/real_testbed.json"
    manifest_path.write_text(json.dumps(rows,indent=2)+"\n")
    real=pd.DataFrame(rows)
    train,val,test=(real[real.split==s] for s in ("train","validation","test"))
    portable=Portable(load_model())
    threshold,options=choose_threshold(portable,val[FEATURES].to_numpy(),val.label.to_numpy())
    results={"evaluation_type":"PRELIMINARY REAL TESTBED EVALUATION",
        "source":"Real strongSwan ESP captures of generated workloads; not organic application traces",
        "sessions":len(real),"groups":12,"classes":sorted(real.label.unique().tolist()),
        "split_sizes":{s:int((real.split==s).sum()) for s in ("train","validation","test")},
        "group_ids":{s:sorted(real[real.split==s].group_id.unique().tolist()) for s in ("train","validation","test")},
        "dataset_sha256":hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "production_model":"Preserved synthetic built-in classifier; experimental models not deployed",
        "synthetic_to_real":{"test":evaluate(portable,test[FEATURES].to_numpy(),test.label.to_numpy()),
            "threshold_selection":options,"abstention":abstention(portable,test[FEATURES].to_numpy(),test.label.to_numpy(),threshold)},
        "real_only":experiment("real_only",train,val,test)}
    synthetic=synthetic_dataset()
    mixed=pd.concat([train,synthetic[synthetic.split=="train"]],ignore_index=True)
    results["mixed_to_real"]=experiment("mixed",mixed,val,test)
    results["cross_crypto"]={}
    for source,target in (("modern","cbc128"),("cbc128","modern")):
        results["cross_crypto"][source+"_to_"+target]=experiment(source+"_to_"+target,
            train[train.configuration==source],val[val.configuration==source],test[test.configuration==target])
    results["limitations"]=["Small single-host dataset; uncertainty is substantial.",
        "Generated VOIP/MESSAGING/VIDEO workloads are not real application/vendor attribution.",
        "All groups share topology and implementation; no external operational validation.",
        "Each split contains entire tunnel-establishment groups; no windows or sessions cross splits.",
        "Cross-crypto test uses only held-out target-profile groups, excluding matching generator seeds from training.",
        "One dominant direction per session; whole-SA multiplexing remains a failure mode.",
        "No calibrated deployment probabilities; thresholds selected on validation only.",
        "The original production classifier and its default 0.60 threshold remain unchanged."]
    (ROOT/"docs/REAL_ML_EVALUATION.json").write_text(json.dumps(results,indent=2)+"\n")
    print(json.dumps({k:{"accuracy":results[k]["test"]["accuracy"],"macro_f1":results[k]["test"]["macro_f1"],
                        "abstention":results[k]["abstention"]} for k in ("synthetic_to_real","real_only","mixed_to_real")},indent=2))


if __name__=="__main__":
    main()
