# Final build report — live validation

**DEMO READY for the isolated local demonstration**, 2026-09-08. This does not certify operational ML accuracy or VPN security. Starting clean SHA: eb87df381057d6f2c97fed9931851cf30b9f8c59; tested implementation e03d4d6; documentation-inclusive final SHA is reported by git rev-parse HEAD in the handoff. Branch feat/sih26160-complete-prototype. Main remains 5087ec8d73c3074c95495393a788e081945b4b8c. No remote configured.

## Live validation

Actual strongSwan 6.0.7 SAs established in isolated user/network/mount namespaces. Docker socket remains unavailable; no group or host VPN changes. Real strong, weak, transport, IPv6 and forced ESP-in-UDP captures passed tshark comparisons. See [LIVE_VALIDATION.md](LIVE_VALIDATION.md) and [machine-readable cross-check](LIVE_PROTOCOL_VALIDATION.json).

Strong: IKE AES256-GCM/PRF-SHA384/ECP384; rekeyed ESP AES256-GCM/ECP384, tunnel, PFS enabled, hard lifetime 3600 s, inbound replay 64, ESN false. 1223 frames / 8 IKE / 1215 ESP. Score 97.5, coverage 100%, ACCEPT.

Weak: IKE CBC128/SHA256/PRF-SHA256/DH14; ESP CBC128/SHA256; PFS disabled, hard lifetime 7200 s, replay64. 1202 frames / 8 IKE / 1194 ESP. Score63.1, coverage80%, PROVISIONAL HARDEN. No SHA1/DH2 finding is claimed.

Transport: established, mode ASSISTED; 28 sequence regressions corroborated by tshark produce REVIEW. IPv6: ordinary outer IPv6 verified. NAT-T: forced UDP encapsulation verified, actual NAT router traversal untested. Raw swanctl and XFRM parsers correlate both endpoints; missing data stays UNKNOWN. Sensor duration, byte limits and interruption cleanup passed in isolation.

## Distinct dataset results

Synthetic baseline: 840 generated profile sessions; original RF held-out synthetic accuracy/macro F1 1.00. This is not real validation.

Real testbed: 120 real encrypted captures of generated workloads, five classes, 12 fresh tunnel groups. Train/validation/test60/20/40, disjoint groups and paired seeds. Original synthetic model on held-out real: accuracy0.45, macro/weighted F1 0.32. Real-only and mixed RF: accuracy/macro/weighted1.00 on40 test sessions. Both cross-crypto directions1.00 on20 held-out target sessions each. Small single-host preliminary evaluation only. Full per-class metrics, Brier/ECE, matrices and split IDs: [REAL_ML_EVALUATION.json](REAL_ML_EVALUATION.json). Experimental threshold0.90 selected on validation; production model and threshold0.60 retained.

## Release checks

Python3.13.14; Node24.19.0. Full Python138 passed (including ML and security regressions; two upstream deprecation warnings). Ruff, mypy backend/training/scripts, compileall and pip check passed. React10 tests, typecheck, lint and production build passed. Real browser walkthrough visited all routes at1366x768 and1920x1080, plus mobile; actual uploads and both report formats downloaded. No application console errors. Offline strong/weak/replay/partial/IPv6 fixture demos remain separately labelled.

Benchmarks on i7-9750H:10k/100k/500k parse0.106/1.111/5.515 seconds, peakRSS54.8/69.4/129.8MiB. One synthetic directional workload on shared host, not a universal performance claim; see BENCHMARK.json.

Fresh review:0 CRITICAL,2 HIGH fixed,5 MEDIUM fixed, no supported open blockers. See [FINAL_SOURCE_REVIEW.md](FINAL_SOURCE_REVIEW.md) and SECURITY_REVIEW.md. Source inventory covers all tracked files; reviewed raw fixtures are redacted. No real capture, secret, database, dependency cache or model pickle was committed. HTML canonical; bounded offline server PDF works with resource fetching disabled.

CI workflow updated and local equivalent checks passed; no remote CI execution because no remote exists. Focused commits preserve history; no main merge. [SIH_MAPPING.md](SIH_MAPPING.md) distinguishes live/offline/partial scope. [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) gives real-first clicks. Previous limitations and measurements remain in BUILD_REPORT_OFFLINE_BASELINE.md as historical evidence, superseded by this report.

## Remaining limits and next improvements

No operational application attribution or calibrated deployment probability; real EMAIL/OTHER absent. Extend independent topology/host/application diversity before changing production model. Docker execution, actual NAT-router traversal and live IPv6 extension chains remain unverified. IKEv1 header-only; AH basic; no fragmentation or ESN reconstruction. Telemetry is trusted operator input, not attested; API is local single-user only. PDF input is bounded. No release blocker for this local demo; these limitations remain in LIMITATIONS.md.
