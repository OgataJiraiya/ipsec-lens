# Final build report · IPsecLens AI

**Status: PARTIAL — working synthetic demonstration; live VPN integration and real-world ML validation remain unverified.**

Build date: 2026-09-08. Tested implementation SHA: fee51d9ab8719d2d8da69886ece8051a6632d259.
This report and the release-evidence commit follow the tested implementation without changing production code; make test now also builds its required classifier artifact.
The final documentation-inclusive SHA is reported in the terminal handoff and can be obtained with git rev-parse HEAD.
main remains at scaffold commit 5087ec8; no development merge was performed.

## Delivery inventory

| # | Requested item | Delivered / verified result |
|---:|---|---|
| 1 | Repository | /home/kali/ipsec-lens-ai |
| 2 | Branch | feat/sih26160-complete-prototype |
| 3 | Git SHA | Tested implementation fee51d9ab8719d2d8da69886ece8051a6632d259; final handoff records documentation-inclusive HEAD |
| 4 | Architecture | Python 3.13 FastAPI/Pydantic/SQLAlchemy/SQLite; stdlib protocol decoding; NumPy/pandas/sklearn; React/TypeScript/Vite |
| 5 | Features | Capture intake, protocol/SA analysis, normalized telemetry, ML, policies, coverage, findings, matrix, HTML reports, dashboard, synthetic demos |
| 6 | IKE | v1 header identification; v2 headers/exchanges/visible proposals/transforms/KE; encrypted contents opaque |
| 7 | ESP | Native and UDP-encapsulated directional SPI statistics and sequence signals |
| 8 | AH | Basic header/SPI/sequence/next-header; no authentication verification |
| 9 | NAT-T | Non-ESP Marker, ESP-in-UDP and keepalive separation |
| 10 | IPv4 | Header/options bounds; fragments explicitly unsupported |
| 11 | IPv6 | Common extension traversal and atomic fragments; explicit unsupported chains |
| 12 | Tunnel/Transport | UNKNOWN by default, matched normalized telemetry ASSISTED; generator supports both |
| 13 | Crypto | IKE transform maps/attributes and separately assisted ESP algorithms; no cross-scope copying |
| 14 | DH | Numeric MODP/ECP/Curve mappings, unknown IDs preserved, policy checks |
| 15 | PFS | ASSISTED configured flag or UNKNOWN; no passive inference |
| 16 | Lifetime | Configured seconds separate from observed SA duration |
| 17 | Replay | Duplicates/regressions/gaps/zero signals separate from configured replay window |
| 18 | Metadata | Endpoints, version, SPI, size, timing, rate and NAT-T remain visible |
| 19 | AI features | 22 directional metadata features; tested bidirectional helper; API inference uses first 2048 packets per directional group |
| 20 | AI model | 100-tree RandomForest selected against LogisticRegression and GradientBoosting |
| 21 | Dataset | 840 synthetic profile sessions; seven classes; no real WhatsApp or deployment captures |
| 22 | Split | Disjoint synthetic configuration/session groups: 504 train / 168 validation / 168 test |
| 23 | Metrics | Synthetic test accuracy/macro F1/weighted F1 1.000; Brier .002114; ECE .008265; not real-world accuracy |
| 24 | Abstention | Configurable .60 threshold; fewer than 20 samples also UNKNOWN |
| 25 | Scoring | Coverage-weighted known-domain averages; risk = 100 − security when available |
| 26 | Coverage | Known/expected checks per SA and domain; below .50 score unavailable; partial provisional |
| 27 | Policies | MODERN, COMPATIBILITY, STRICT |
| 28 | Threat matrix | Backend finding/unknown rows with evidence, severity, confidence, impact and remediation |
| 29 | Testbed | Five deterministic synthetic scenarios; isolated Docker generator; daemon denied live verification |
| 30 | Strong demo | 386 packets, 97.5 security / 2.5 risk, 100% coverage, AVAILABLE, ACCEPT, no HIGH/CRITICAL |
| 31 | Weak demo | 386 packets, 30.5 security / 69.5 risk, 100% coverage, AVAILABLE, HARDEN |
| 32 | Replay demo | 386 packets, duplicate/regression/gap findings, 20% coverage, UNAVAILABLE, REVIEW |
| 33 | Partial evidence | 384 packets, 5% coverage, UNAVAILABLE, REVIEW; configuration fields UNKNOWN |
| 34 | IPv6 demo | 387 packets including AH, 96.6 security, 73.3% coverage, PROVISIONAL, REVIEW |
| 35 | Executive report | Standalone escaped HTML, API and real browser download verified |
| 36 | Technical report | Full evidence/SA/ML/matrix/domain/provenance HTML, browser download verified |
| 37 | Backend tests | 92 passed (protocol 39, semantics 17, API 15, hardening 21) |
| 38 | ML tests | 9 passed, including repeated byte-identical training and abstention |
| 39 | Full Python | 101 passed, 2 upstream deprecation warnings; compileall, Ruff, mypy and pip check passed |
| 40 | Frontend tests | 8 passed; upload/errors/unknowns/filtering/reports/selection-race behavior |
| 41 | Frontend build | TypeScript, ESLint, Vitest and Vite production build passed; clean offline npm ci succeeded |
| 42 | CI | Python/frontend workflow committed; no remote run/push claimed |
| 43 | Source review | Completed; semantic/resource/UI defects corrected; see SOURCE_REVIEW.md |
| 44 | Security review | Completed within local prototype scope; residual risks documented, no independent audit claimed |
| 45 | Limits | Synthetic ML; unverified live lab; raw endpoint text import, reassembly, authentication and server PDF absent |
| 46 | SIH mapping | docs/SIH_MAPPING.md maps requirements with COMPLETE/PARTIAL/NOT IMPLEMENTED |
| 47 | Files | 100 tracked files after release-evidence commit; captures limited to small synthetic fixtures |
| 48 | Commits | 13 meaningful commits including scaffold and release evidence; development not merged into main |
| 49 | Blockers | Docker daemon permissions; real labelled IPsec capture validation not established |
| 50 | Next improvements | Verify isolated live lab, collect independent real local datasets, calibrate/evaluate domain shift, add redacting endpoint adapters and broader protocol tests |

## Release procedure and evidence

- Recreated synthetic demo state with make clean-demo followed by make demo.
- Ran full Python suite against temporary per-test databases and fixtures.
- Validated Python 3.13.14 and Node v24.19.0.
- Ran compileall, Ruff, mypy and pip dependency consistency check.
- Clean frontend dependency installation from cached packages with npm ci --offline.
- Frontend typecheck, lint, 8 tests and production build passed.
- Fresh Chromium uploads: strong, weak, replay, partial, IPv6.
- Nine detail/system/demo views plus Overview/New Analysis exercised.
- Both report downloads verified as newly created files.
- Browser viewports: 1366×768, 1920×1080, 390×844; no page-width overflow or application console errors.
- Screenshots and browser evidence: runtime/browser/. Reports: runtime/demo-reports/.
- Structured test/demo/model evidence: docs/RELEASE_VALIDATION.json.
- Source review includes pattern searches and checks of all repository-owned production layers.
- No secrets, real user captures, model pickles, runtime database, dependency directories or caches committed.
- No remote CI run, external scan, active attack or successful live VPN integration claimed.

The sandbox required escalation for dependency installation, threaded API tests and loopback browser services.
Docker daemon remained permission-denied even after escalation, so no live VPN was reported working.
Frontend offline reinstall initially hit sandbox EPERM during esbuild validation; retry outside sandbox succeeded.
These environment issues did not invalidate the completed local synthetic analyzer tests.

## Measured performance

Intel Core i7-9750H / Linux, Python 3.13.14; single synthetic directional ESP flow.

| Packets | Parse seconds | Peak process RSS MiB |
|---:|---:|---:|
| 10,000 | 0.111 | 54.75 |
| 100,000 | 1.193 | 69.63 |
| 500,000 | 6.189 | 130.02 |

First model load/inference approximately 5–6 ms; feature extraction approximately 1 ms; report generation
below 1 ms for these aggregated reports. These are measurements of one workload, not a performance SLA.
Peak RSS includes imports/model/repeated analysis. See BENCHMARK.json for raw values and caveats.

## Demo interpretation

Scenario success refers to real analysis of labelled synthetic inputs, not cryptographic proof of a
functioning VPN. The modern score relies on matching generated ASSISTED telemetry. Uploading that PCAP
without telemetry correctly leaves Child-SA crypto, mode, PFS, lifetime and replay window UNKNOWN.
Perfect synthetic classifier performance does not establish real application recognition.
