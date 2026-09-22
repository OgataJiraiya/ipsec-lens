# IPsecLens experimental encrypted-flow metadata classifier

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

## SYNTHETIC VALIDATION
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

## REAL TESTBED VALIDATION

Preliminary evaluation: 120 real ESP captures of generated local workloads, five classes, 12 isolated strongSwan tunnel groups. Group-safe train/validation/test = 60/20/40. Both AES-GCM and AES-CBC; no session or paired workload seed crosses splits.

| Training | Held-out real accuracy | Macro F1 | Weighted F1 | Brier | ECE |
|---|---:|---:|---:|---:|---:|
| Original synthetic | 0.45 | 0.32 | 0.32 | 0.5130825 | 0.307 |
| Real-only RF | 1.00 | 1.00 | 1.00 | 0.000295 | 0.006 |
| Mixed RF | 1.00 | 1.00 | 1.00 | 0.00025875 | 0.006 |

RF/LR/GradientBoosting selection and threshold selection used validation only. Experimental threshold 0.90; synthetic-model coverage 0.40 with 24/40 abstentions, real/mixed coverage 1.00. Both held-out cross-crypto directions scored macro F1 1.00 on 20 target sessions. Full distributions, candidate metrics and group IDs: ../docs/REAL_ML_EVALUATION.json.

The production artifact remains synthetic-trained at threshold 0.60. Poor transfer (macro F1 0.32) is material. Perfect lab-trained results reflect a small, controlled single-host experiment with only four held-out tunnel groups; no deployment, vendor/application attribution or calibrated operational confidence claim is supported. EMAIL/OTHER lack real samples. Generated workload labels are not organic application traces.

## Product presentation

EXPERIMENTAL. System and Encrypted Traffic AI show the built-in model type/hash, training
source, 22-feature count, current runtime threshold, separately labelled synthetic metrics and
controlled held-out real macro F1 0.32. Payload decrypted: NO. Real-world application attribution
validated: NO. Values come from fixed local model/evaluation files; no external runtime metadata.
The production artifact and its committed SHA-256 are unchanged by this release pass.
