# Final build report — live validation

**DEMO READY for the isolated local demonstration**, 2026-09-08. This does not certify operational ML accuracy or VPN security. Starting clean SHA: eb87df381057d6f2c97fed9931851cf30b9f8c59; live-validation implementation e03d4d6; original documentation-inclusive handoff SHA cc21c4499f1621c97b140f03ed03fc54b18f7a04. Branch `feat/sih26160-complete-prototype`; main remains `5087ec8d73c3074c95495393a788e081945b4b8c`. Remote repository is `OgataJiraiya/ipsec-lens`; PR #1 contains the release candidate and remains unmerged.

## Live validation

Actual strongSwan 6.0.7 SAs established in isolated user/network/mount namespaces. Docker socket remains unavailable; no group or host VPN changes. Real strong, weak, transport, IPv6 and forced ESP-in-UDP captures passed tshark comparisons. See [LIVE_VALIDATION.md](LIVE_VALIDATION.md) and [machine-readable cross-check](LIVE_PROTOCOL_VALIDATION.json).

Strong: IKE AES256-GCM/PRF-SHA384/ECP384; rekeyed ESP AES256-GCM/ECP384, tunnel, PFS enabled, hard lifetime 3600 s, inbound replay 64, ESN false. 1223 frames / 8 IKE / 1215 ESP. Score 97.5, coverage 100%, ACCEPT.

Weak: IKE CBC128/SHA256/PRF-SHA256/DH14; ESP CBC128/SHA256; PFS disabled, hard lifetime 7200 s, replay64. 1202 frames / 8 IKE / 1194 ESP. Score 63.1, coverage 80%, PROVISIONAL HARDEN. No SHA1/DH2 finding is claimed.

Transport: established, mode ASSISTED; 28 sequence regressions corroborated by tshark produce REVIEW. IPv6: ordinary outer IPv6 verified. NAT-T: forced UDP encapsulation verified, actual NAT router traversal untested. Raw swanctl and XFRM parsers correlate both endpoints; missing data stays UNKNOWN. Sensor duration, byte limits and interruption cleanup passed in isolation.

## Distinct dataset results

Synthetic baseline: 840 generated profile sessions; original RF held-out synthetic accuracy/macro F1 1.00. This is not real validation.

Real testbed: 120 real encrypted captures of generated workloads, five classes, 12 fresh tunnel groups. Train/validation/test 60/20/40, disjoint groups and paired seeds. Original synthetic model on held-out real: accuracy 0.45, macro/weighted F1 0.32. Real-only and mixed RF: accuracy/macro/weighted 1.00 on 40 test sessions. Both cross-crypto directions 1.00 on 20 held-out target sessions each. Small single-host preliminary evaluation only. Full per-class metrics, Brier/ECE, matrices and split IDs: [REAL_ML_EVALUATION.json](REAL_ML_EVALUATION.json). Experimental threshold 0.90 selected on validation; production model and threshold 0.60 retained.

## Release checks

Local validation used Python 3.13.14 and Node 24.19.0. The first hosted PR validation and the post-audit hardening validation both passed on GitHub Actions. Hardening run `34202981510` validated head `8ae6a737d710914b2b737349402b5f609a34aab5` on Ubuntu 24.04 with Python 3.13.15 and Node 24.20.0: **142 Python tests passed** (two upstream deprecation warnings), compileall/Ruff/mypy passed, deterministic model regeneration reproduced SHA-256 `ccf24a3017e7715ff203e5ee311ac97957d6168702b63f26ff7f19cc5c78ecad`, demo scenarios passed, and frontend typecheck/lint/**10 tests**/production build passed. GitHub Actions are pinned to the exact reviewed action commits.

The earlier real browser walkthrough visited all routes at 1366x768 and 1920x1080, plus mobile; actual uploads and both report formats downloaded with no application console errors. Offline strong/weak/replay/partial/IPv6 fixture demos remain separately labelled.

Benchmarks on i7-9750H: 10k/100k/500k parse 0.106/1.111/5.515 seconds, peak RSS 54.8/69.4/129.8 MiB. One synthetic directional workload on shared host, not a universal performance claim; see BENCHMARK.json.

The original internal review found 0 CRITICAL, 2 HIGH and 5 MEDIUM supported issues and fixed them. A subsequent independent GitHub release audit added three supported MEDIUM hardening fixes (total PCAPNG block-work ceiling, host-root tcpdump privilege drop, and IKE-version policy resilience past message-retention limits) plus LOW CI supply-chain pinning. All received regression coverage and passed hosted CI. See [FINAL_SOURCE_REVIEW.md](FINAL_SOURCE_REVIEW.md), [EXTERNAL_RELEASE_AUDIT.md](EXTERNAL_RELEASE_AUDIT.md), and SECURITY_REVIEW.md. No real capture, secret, database, dependency cache or model pickle is committed. HTML remains canonical; bounded offline server PDF works with resource fetching disabled.

[SIH_MAPPING.md](SIH_MAPPING.md) distinguishes live/offline/partial scope. [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) gives real-first clicks. Previous limitations and measurements remain in BUILD_REPORT_OFFLINE_BASELINE.md as historical evidence, superseded by this report.

## Remaining limits and next improvements

No operational application attribution or calibrated deployment probability; real EMAIL/OTHER absent. Extend independent topology/host/application diversity before changing production model. Docker execution, actual NAT-router traversal and live IPv6 extension chains remain unverified. IKEv1 header-only; AH basic; no fragmentation or ESN reconstruction. Telemetry is trusted operator input, not attested; API is local single-user only. PDF input is bounded. No release blocker for this local demo; these limitations remain in LIMITATIONS.md.
