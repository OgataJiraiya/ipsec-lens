# Reproducible synthetic dataset

manifests/synthetic.json contains 840 session records with deterministic seed, label, group and split.
Generate feature rows with python -m training.extract_features; CSV output is ignored under generated/.
Generate PCAP demos with python -m scripts.fixtures. Small committed PCAPs total under 500 KiB.
All fixtures are SYNTHETIC FIXTURE data. Dummy KE bytes and opaque ESP bytes are not an encrypted VPN session.

No captured personal communications or external services are contacted.
Dataset labels describe generator workload shapes. They are not proof that real ESP contains an application.
ICMP shape is periodic small traffic; EMAIL/WEB/VOIP/MESSAGING/VIDEO are synthetic metadata profiles.
The optional lab offers ping/curl and a lab-subnet-only UDP profile emitter; these are not yet an
end-to-end captured, independently labelled real traffic dataset.
