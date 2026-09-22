# Reproducible synthetic dataset

manifests/synthetic.json contains 840 session records with deterministic seed, label, group and split.
Generate feature rows with python -m training.extract_features; CSV output is ignored under generated/.
Generate PCAP demos with python -m scripts.fixtures. Small committed PCAPs total under 500 KiB.
All fixtures are SYNTHETIC FIXTURE data. Dummy KE bytes and opaque ESP bytes are not an encrypted VPN session.

No captured personal communications or external services are contacted.
Dataset labels describe generator workload shapes. They are not proof that real ESP contains an application.
ICMP shape is periodic small traffic; EMAIL/WEB/VOIP/MESSAGING/VIDEO are synthetic metadata profiles.
The namespace lab now captures ping/curl and local generated UDP workloads end-to-end through real ESP. See manifests/real_testbed.json for capture hashes, group IDs, labels and extracted features; private captures remain under ignored runtime/live.

## Live validation update

See [../docs/LIVE_VALIDATION.md](../docs/LIVE_VALIDATION.md) for real strong/weak, transport, IPv6 and forced NAT-T verification. Real generated-workload dataset: 120 sessions; group-safe preliminary evaluation is recorded separately from synthetic metrics. Production retains the original synthetic classifier; its held-out real macro F1 is 0.32. HTML and bounded offline server PDF reports are verified.
