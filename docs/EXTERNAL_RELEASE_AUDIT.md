# External GitHub release audit — 2026-09-08

This addendum records the independent release review performed after the project was pushed to `OgataJiraiya/ipsec-lens` and PR #1 was opened. The review was performed against the feature branch rather than relying on the project's own internal review report.

## Scope reviewed

The review sampled and cross-checked the primary trust and correctness boundaries: bounded PCAP/PCAPNG ingestion, Ethernet/SLL/IP decoding, IKE parsing, ESP/AH/NAT-T flow handling, telemetry correlation, evidence semantics, scoring, SQLite persistence, HTML/PDF reporting, local capture privileges, isolated strongSwan testbed, real/synthetic ML evaluation, React stale-response behavior, API upload/origin/host protections, test coverage, and CI configuration.

The existing internal review remained useful evidence, but was not treated as proof of correctness by itself.

## Supported findings from the external pass

| Severity | Finding | Resolution |
|---|---|---|
| MEDIUM | PCAPNG packet ceilings did not also bound the number of metadata/unknown blocks, so a large capture containing many tiny non-packet blocks could consume excessive CPU without hitting the packet limit. | Added a total PCAPNG block-work ceiling and a regression containing thousands of non-packet blocks. |
| MEDIUM | The standalone capture sensor constructed `tcpdump -Z` from the current uid. Under a normal `sudo` invocation that uid is root, which unnecessarily kept tcpdump at host-root privilege after capture setup. | The sensor now drops to validated `SUDO_UID`, preserves mapped namespace-root only when it maps to an unprivileged host uid, otherwise uses the dedicated `tcpdump` account or refuses. Regression tests cover sudo and true-host-root cases. |
| MEDIUM | Protocol-hygiene scoring derived the observed IKE version only from retained detailed IKE messages. If the detailed-message retention ceiling was reached, a later IKEv1 observation could be counted by the parser but omitted from the policy finding. | Version policy now uses all-message counters first and detailed messages only as a compatibility fallback. A regression verifies an IKEv1 count cannot disappear behind retention. |
| LOW | GitHub Actions referenced moving major-version tags. | CI actions are pinned to the exact commits resolved by the first successful hosted run, with major-version comments retained for maintainability. |

No new CRITICAL or HIGH issue was supported by this external pass within the documented single-user, loopback/offline prototype scope.

## Hosted validation after fixes

PR #1 hardening head `8ae6a737d710914b2b737349402b5f609a34aab5` was validated by GitHub Actions run `34202981510` (`IPsecLens quality gates`) on Ubuntu 24.04.

- Python 3.13.15: **142 passed**, two upstream deprecation warnings.
- `compileall`: PASS.
- Ruff: PASS.
- mypy: PASS across 54 source files.
- Deterministic model regeneration reproduced SHA-256 `ccf24a3017e7715ff203e5ee311ac97957d6168702b63f26ff7f19cc5c78ecad`.
- Offline demo scenarios: strong 97.5/ACCEPT, weak 30.5/HARDEN, replay and partial score UNAVAILABLE, IPv6 PROVISIONAL/REVIEW.
- Frontend: typecheck PASS, lint PASS, **10 tests passed**, production build PASS.
- `npm ci` reported zero known vulnerabilities at the time of this run.

The hosted CI does not execute privileged strongSwan integration. Live strongSwan/XFRM/tshark evidence remains the locally measured validation recorded in `LIVE_VALIDATION.md`; hosted CI independently validates the unprivileged source, parser, policy, ML fixture, report, and frontend regression gates.

## Residual scope limits

The external pass does not turn the prototype into a production VPN assurance product. The existing limits remain: endpoint telemetry is trusted rather than attested; IKEv1 is header-level only; AH is basic; IP fragmentation and ESN reconstruction are unsupported; actual NAT-router traversal and Docker execution are not validated; the API is intentionally loopback/single-user; and the production traffic classifier is still synthetic-trained with poor synthetic-to-real transfer (held-out real macro F1 0.32). The real-only 1.00 laboratory metrics remain preliminary generated-workload results, not operational accuracy claims.

Within that stated scope, no supported release-blocking correctness or security defect remains from this external review.
