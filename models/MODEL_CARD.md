# IPsecLens synthetic metadata classifier

## Intended use
Demonstrate reproducible encrypted-flow metadata feature extraction, model selection, inference and abstention.
Not suitable for operational application attribution or automated enforcement.

## Training source
SYNTHETIC FIXTURE profile generator; no real user traffic, no WhatsApp captures, no deployment PCAP labels.
Labels: VOIP, MESSAGING, EMAIL, WEB, ICMP, VIDEO, OTHER.
These name synthetic workload shapes, not proven applications inside actual ESP.

840 synthetic sessions, 10 disjoint group identifiers; train/validation/test = 504/168/168.
Feature schema: 22 outer-length/timing/count features, documented in AI_TRAFFIC_CLASSIFIER.md.
Seed 26160. CPU training, single-thread forest. Dependencies pinned in requirements.lock.

## Model selection and measured metrics
Selected RandomForestClassifier against LogisticRegression and GradientBoosting using validation macro F1.
Synthetic held-out test: accuracy 1.000, macro F1 1.000, weighted F1 1.000.
All seven classes have precision/recall/F1 1.000, with 24 test examples per class.
Confusion matrix diagonal = 24 for each class; all off-diagonal entries zero.
Multiclass Brier score: 0.00211377. Ten-bin expected calibration error: 0.00826488.
Full candidate validation metrics and test matrix are produced in models/metrics.json.
Artifact metadata stores dataset, manifest and model hashes; model bytes reproduce with the pinned environment.

**Perfect synthetic metrics reflect deliberately separable generator profiles.
They do not measure real encrypted traffic classification accuracy or resistance to domain shift.**
Configuration groups do not establish generalization across actual VPN implementations or ciphers.

## Confidence and abstention
Maximum class probability, uncalibrated. Default confidence threshold 0.60.
Below threshold or fewer than 20 packets → UNKNOWN.
No cloud/LLM. No payload access. No attack probability interpretation.
No exact-application, WhatsApp, OS, vendor, version or CVE identification.

## Known failure modes
Multiplexed applications within one SA; short captures; asymmetric paths; fragmentation;
padding, MTU, transport overhead, burst scheduling, loss, capture offload and timestamp resolution;
tunnels carrying multiple users; traffic shaping; workloads outside synthetic distributions.
First 2048 packets may not represent a long-lived SA. Confident errors remain possible.

## Artifact safety
Built-in JSON only. No pickle/joblib import path exposed to users.
SHA-256 detects accidental artifact mismatch, not malicious replacement by a trusted local operator.
Real-world calibrated confidence and externally validated datasets remain future work.
