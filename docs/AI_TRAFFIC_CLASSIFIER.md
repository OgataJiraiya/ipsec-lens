# Metadata classifier

See [Model card](../models/MODEL_CARD.md) for metrics and limitations.

Pipeline commands:

    .venv/bin/python -m training.generate_manifest
    .venv/bin/python -m training.extract_features
    .venv/bin/python -m training.train
    .venv/bin/python -m training.evaluate

840 independent synthetic sessions; configuration-group splits 504 train / 168 validation / 168 test.
Six group IDs train, two validation, two test. Each group includes all seven labels and 12 sessions per label.
These are synthetic generator groups, not independently captured real VPN configurations.
No adjacent packet rows, session IDs, seed, label, address, SPI or group ID enter the model.

Candidates: RandomForest (100 trees, depth 9, leaf minimum 2), standardized LogisticRegression,
GradientBoosting (60 stages, depth 2). Random seed 26160. Highest validation macro F1 selects the model;
candidate order breaks ties. Only then evaluate test. Reproducibility test trains twice and compares bytes.
No retraining on test, no test-set hyperparameter tuning. No claimed probability calibration.

## Features (directional first-2048-packet prefix)

Packet count and byte count: number/sum of outer IP lengths.
Mean, population standard deviation, minimum and maximum outer packet size.
Small ratio: length <200; large ratio: length >=1200.
Duration: last sorted timestamp minus first timestamp.
Packets/s and bytes/s: corresponding total / duration; zero for zero duration.
IAT: nonnegative differences of sorted timestamps, mean and population std.
Burstiness: (IAT std − mean)/(std + mean), zero when denominator zero.
Size histogram proportions: [0,200), [200,600), [600,1200), [1200,∞).
IAT proportions: [0,.005), [.005,.05), [.05,.5), [.5,∞).

An additional tested bidirectional helper aggregates two supplied directions and reports direction ratio
and count asymmetry. The API classifier deliberately uses directional groups because opposite SPIs are
not proven to be the same Child SA. Automatic bidirectional association is not implemented.

## Artifact

Fixed models/classifier.json contains class mapping, feature schema, forest trees, training metadata
and metrics. Dataset SHA hashes canonical generated feature rows and manifest SHA is also recorded.
Artifact SHA-256 is checked against models/classifier.sha256. Neither input paths nor model uploads
can choose the model. JSON traversal cannot execute Python code. File integrity is not a signature:
a local operator able to replace both files is trusted.

Run make train after changing a model and restart the backend to clear its process cache.
Threshold uses IPSECLENS_ABSTENTION (default 0.60); fewer than 20 samples abstains as UNKNOWN.
Confidence below threshold also abstains; probabilities remain visible.
Low confidence is not the only failure mode: synthetic domain shift can be confidently wrong.

Encrypted payload was not decrypted. Classification is statistical flow-metadata inference.

## Live validation update

See [../docs/LIVE_VALIDATION.md](../docs/LIVE_VALIDATION.md) for real strong/weak, transport, IPv6 and forced NAT-T verification. Real generated-workload dataset: 120 sessions; group-safe preliminary evaluation is recorded separately from synthetic metrics. Production retains the original synthetic classifier; its held-out real macro F1 is 0.32. HTML and bounded offline server PDF reports are verified.
