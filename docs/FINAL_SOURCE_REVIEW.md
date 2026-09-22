# Fresh final source review — 2026-09-08

Internal engineering review; not an independent audit. Starting baseline eb87df381057d6f2c97fed9931851cf30b9f8c59. Reviewed implementation through e03d4d6 plus final browser/inventory scripts and documentation. Main was not changed.

All 158 files tracked before this documentation pass were read and inventoried by scripts/review_inventory.py, including protocol/API/ML/React source, testbed, tests, raw fixtures, manifests, dependency locks, CI and documents. Python AST parsing and requested sensitive-pattern searches supplemented source inspection; inventory output is runtime/final-review-inventory.json. Automated inventory alone is not a correctness audit.

| Severity | Supported issues | Fixed | Open |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 2 | 2 | 0 |
| MEDIUM | 5 | 5 | 0 |

| Severity | Finding and correction | Regression evidence |
|---|---|---|
| HIGH | Privileged capture destination race: exclusive O_EXCL/O_NOFOLLOW creation, no overwrite | test_capture_sensor.py |
| HIGH | New raw parser could treat optional NONE/DH proposal as mandatory PFS: preserve UNKNOWN | test_live_telemetry.py |
| MEDIUM | Sensor output could exceed intended disk bound: streamed byte ceiling and packet limit | sensor tests and live byte failure |
| MEDIUM | Interrupted sensor could retain incomplete output: finally cleanup and process termination | live SIGINT and tests |
| MEDIUM | EtherType/IP-version disagreement could misidentify encapsulation: reject inconsistent packet | protocol regression |
| MEDIUM | Initial frontend history response could override user selection: selectionTouched guard | App tests |
| MEDIUM | Malformed raw telemetry nested shapes could escape clean parser errors: explicit shape checks | raw parser tests |

## Reviewed boundaries

PCAP/PCAPNG record allocation and packet ceilings; IPv4 fragments rejected; bounded IPv6 extensions and unsupported chains; IKE header/payload/proposal lengths and encrypted-chain termination; IKEv1 header-only claims; NAT-T marker/keepalive distinction; native/UDP ESP; basic AH. Directional SPI grouping and sequence signals remain separate from replay policy. Wrap/ESN reconstruction is not claimed. No IKE-SA transforms are promoted into Child-SA crypto.

Telemetry matches exact endpoint/protocol/SPI and capture identity. Actual local raw samples exposed GCM salt-bit, extended replay-window, ESN-heading and remaining-lifetime interpretation hazards: the new adapter handles these explicitly with regression tests. Both endpoints are required where receiver policy is needed. Missing/conflicting evidence cannot silently become secure.

Scoring excludes unknown checks from secure credit and displays coverage/status. Severe policy findings override ACCEPT; transport regressions demonstrate REVIEW despite high configuration score. ML groups exclude shared tunnel sessions and paired workload seeds. Model/threshold selection precedes test use. Production artifact is fixed trusted JSON; no uploaded executable serialization.

Uploads use bounded spooling, safe generated paths, transactions and cleanup. SQLite write concurrency remains bounded. React uses text escaping and stale-response guards. HTML escapes values; PDF disallows resource fetches and bounds input/concurrency. Subprocesses use argument arrays. Isolated lab namespaces have no external route; private runtime keys stay ignored. CI covers unprivileged tests, not privileged integration.

Requested TODO/FIXME/shell=True/eval(/exec( hits in the pre-documentation inventory were review search strings in docs, not executable call sites. Pickle/joblib references were documentation and dependency metadata; no untrusted model loading. Mock/placeholder matches were test utilities or input labels; pass sites were exception/cleanup handling or prose, not unfinished analyzer behavior. No innerHTML or os.system call was found. Synthetic fixtures are explicitly labelled test inputs, never precomputed analysis results.

## Residual limitations (INFO)

Loopback single-user service has no public/multi-tenant authentication. Endpoint telemetry is not attested. OS kills may leave temporary files. No fragmentation/ESN reconstruction, payload authentication or decryption. PDF has a size ceiling. Docker was not executed. Small generated-workload real dataset does not establish deployment accuracy; synthetic-model transfer is poor. These remain documented scope limits, not hidden secure assertions.

Validation: 138 Python tests, Ruff, mypy, compileall; 10 React tests, typecheck/lint/build; actual browser uploads and HTML/PDF downloads; five live protocol cross-checks; capture sensor lifecycle. No supported release-blocking correctness/security issue remains from this review.

## Final pre-merge addendum — 2026-09-22

Reviewed new JSON export, exact-ID deletion, directory descriptor/no-follow capture cleanup,
DB rollback/retry/concurrent writer behavior, mutation Host/Origin/body controls, React
comparison/provenance/model panels, typed unknown semantics and stale lifecycle responses.
No new arbitrary model/metadata paths, raw HTML rendering, secret fields or permissive CORS.
No supported new HIGH/MEDIUM issue remains open in this bounded local-prototype review.

20 new Python and 18 new frontend cases pass; total 162 Python / 28 frontend. All thirteen
pages, actual report/JSON downloads and confirmed disposable deletion pass Chromium checks.
Known tradeoff: capture unlink precedes DB commit; commit failure leaves a retryable row
with absent retained capture. Logical deletion is not forensic erasure of DB pages/backups.
Full evidence and corrected presentation issues: [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
