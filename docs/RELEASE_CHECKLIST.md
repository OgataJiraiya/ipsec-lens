# Final pre-merge release checklist — 2026-09-22

Scope: SIH 26160 / NTRO local, single-user prototype. This is an internal engineering pass,
not security certification. Main is not merged or changed.

## Source and hosted evidence

- Starting clean HEAD: `accfe47da8a403905b6d1deb369b1bfba28e7052`.
- Branch: `feat/sih26160-complete-prototype`; PR #1; base main `5087ec8d73c3074c95495393a788e081945b4b8c`.
- Feature implementation: `6b9836037ca4bf39f9ea733f9e4ac3d377717b6e`.
- Complete tested code and gate scripts: `2a2dcef47978394234450a78baa69de5a2fc0235`.
- Documentation commits follow that tested code; use `git rev-parse HEAD` for the final documentation-inclusive revision.
- Starting release candidate validated by GitHub Actions at the documented release head:
  [successful run 34203307597](https://github.com/OgataJiraiya/ipsec-lens/actions/runs/34203307597),
  independently queried through the GitHub connector in this pass. This supersedes the older
  hardening-head reference without inventing a future SHA. Post-push checks for the final
  branch tip are reported separately in the delivery handoff, not inferred from this prior run.

## Checks performed

Python 3.13.15; Node 24.19.0; npm 11.19.0. Installed pinned dependencies were used;
no dependency changes or new dependency installation was necessary.

| CHECK | RESULT | EVIDENCE |
|---|---|---|
| Starting branch / SHA / clean tree | PASS | Git status, branch, rev-parse and last 15 commits inspected before edits |
| `make test` | PASS | 162 Python + 28 frontend tests; static/build gates; `/tmp/ipseclens-make-test.log` |
| `make release-check` | PASS | Deterministic artifact, pytest, compileall, Ruff, mypy, demos, frontend gates; `/tmp/ipseclens-release-check.log` |
| Explicit `.venv/bin/python -m pytest -q` | PASS | 162 passed, two upstream deprecation warnings; `/tmp/ipseclens-pytest.log` |
| Explicit compileall | PASS | `-q backend training scripts`, exit 0 |
| Explicit Ruff | PASS | `ruff check .`, all checks passed |
| Explicit mypy | PASS | 56 source files, no issues |
| Explicit frontend typecheck / lint / tests / build | PASS | 28 tests in two files, tsc/ESLint/Vite success; `/tmp/ipseclens-frontend-build.log` |
| Model integrity / deterministic regeneration | PASS | Unchanged SHA-256 `ccf24a3017e7715ff203e5ee311ac97957d6168702b63f26ff7f19cc5c78ecad` |
| Explicit offline demo | PASS | `runtime/demo-reports/results.json`; `/tmp/ipseclens-demo.log`; table below |
| Chromium / Selenium walkthrough | PASS | 13 pages × 2 desktop sizes; five uploads; `runtime/browser/walkthrough.json` |
| Report / JSON downloads | PASS | Newly created executive + technical HTML/PDF and typed JSON; PDF signature and JSON identity/score checked |
| Confirmed deletion | PASS | Disposable browser-created run only; selected run cleared; API retry/concurrency/storage regressions |
| 1366×768 / 1920×1080 | PASS | No page-width overflow; navigation scrolls; comparison and Overview screenshots inspected |
| 390×844 Overview | PASS | No page-width overflow; existing mobile smoke check retained |
| Browser console | PASS | No application SEVERE errors (favicon excluded) |
| Security boundary review | PASS within local scope | See final additions in SECURITY_REVIEW.md and lifecycle regressions |
| Secret / capture inventory | PASS | Only `.env.example` and five known synthetic PCAPs match sensitive-path inventory; ten XFRM fixtures redacted |
| Scoring / production model preservation | PASS | No diff in policy, scoring implementation, classifier, model digest or REAL_ML_EVALUATION.json |
| Whitespace / explicit staging | PASS | `git diff --check`; reviewed explicit file lists, no blanket add |
| Privileged/live re-establishment | NOT RUN in this pass | Remains separate; previous measured results retained in LIVE_VALIDATION.md |

The sandbox stalled threaded TestClient execution; the stalled attempt was stopped and
all API/full gates completed outside that sandbox as the same unprivileged user. Browser
loopback services also required sandbox escalation. This did not invoke namespace/Docker
operations or change host VPN state. Temporary logs and browser artifacts remain untracked.

## Demo evidence — all SYNTHETIC FIXTURE

| Scenario | Packets | Security / risk | Coverage | Score status | Disposition |
|---|---:|---|---:|---|---|
| Strong + matching telemetry | 386 | 97.5 / 2.5 | 100% | AVAILABLE | ACCEPT |
| Weak + matching telemetry | 386 | 30.5 / 69.5 | 100% | AVAILABLE | HARDEN |
| Replay | 386 | UNKNOWN / UNKNOWN | 20% | UNAVAILABLE | REVIEW |
| Partial | 384 | UNKNOWN / UNKNOWN | 5% | UNAVAILABLE | REVIEW |
| IPv6 + matching ESP telemetry, basic AH | 387 | 96.6 / 3.4 | 73.3333% | PROVISIONAL | REVIEW |

Strong has known weighted checks; that is not authenticated endpoint truth. Weak preserves
DH/PFS/lifetime/replay hardening findings. Replay preserves duplicate/regression/gap signals
without asserting replay acceptance. Partial Child-SA properties remain UNKNOWN. IPv6 AH
configuration remains UNKNOWN and reduces coverage. Real weak remains the separate prior
63.1/80% measurement, not the synthetic weak result.

## Added regression coverage

20 Python cases: typed current-revision export and safe headers; invalid/missing identities;
retained/nonretained deletion; other-analysis preservation; missing capture retry; file and
directory symlink/nonregular refusal; cleanup rollback; commit-failure retry; concurrent
deletes and stale telemetry replacement; DELETE origin/host/body controls; hash-based fixture
provenance and report disclosure.

18 frontend cases: valid/unknown/missing comparison selections; score and coverage deltas;
false/zero handling; exact SA matching; finding changes; stale fetches and removed history;
all-message IKE version display; provenance/abstention; model metadata/caveats/failure states;
confirmation/cancel/error/retry; JSON download links; deletion clearing despite stale history;
selection changes during deletion; no unrelated global synthetic banner on comparisons.
Original 142 Python and 10 frontend cases remain passing.

## Audit findings and decisions

- Documentation already recorded successful hosted CI, but cited an older hardening head.
  Updated the starting-head reference to a verified successful run; historical reports remain labelled.
- Overview derived IKE versions only from retained messages. Corrected to all-message counters
  with the existing compatibility fallback; scoring was already correct and remains unchanged.
- Synthetic labeling previously depended on imported telemetry. Added a typed bundled-hash
  match so passive replay/partial captures are labelled too; nonmatching captures stay UNVERIFIED.
- History refreshes and late report responses needed lifecycle-aware stale-state guards.
  Added request ordering, deleted-ID filtering, abort checks and per-analysis confirmation state.
- New DELETE routes are included in mutation protections. Capture deletion uses generated IDs,
  anchored directory descriptors, no-follow opens, nonregular refusal and transaction rollback.
- Comparison review caught a global synthetic banner referring to another selected run; removed
  it from comparison and retained per-snapshot provenance.

No supported new HIGH or MEDIUM security issue remains open in this pass. Existing parser,
upload, telemetry, report, host/origin and model-upload boundaries were retained. This review
is bounded engineering evidence, not an exhaustive adversarial or independent security audit.

## Known limitations and merge readiness

Local release gates: PASS; ready for manual merge review within the documented prototype scope.
Final hosted tip validation and final clean-tree/push evidence belong to the delivery handoff.
Do not merge automatically. No PARTIAL / NOT IMPLEMENTED SIH requirement was upgraded.

Production ML remains EXPERIMENTAL, synthetic-trained, uncalibrated and poor at synthetic-to-real
transfer (controlled held-out real macro F1 0.32). No real-world application attribution or
payload decryption. Telemetry is trusted operator input, not attestation. IKEv1/AH remain
limited; no fragmentation, ESN reconstruction or cryptographic authentication verification.
Docker, actual NAT-router traversal and deployment ML accuracy remain unverified.

Comparison uses the currently loaded recent history (the existing 50-row history window),
exact directional SA identities and snapshot finding identities; no causal remediation or
rekey matching. Deletion is logical, not forensic erasure; independent downloads/backups are
unaffected. A crash/commit failure after capture unlink may leave a row with missing capture;
retry completes deletion. No generic purge, scheduling or public/multi-user service was added.
