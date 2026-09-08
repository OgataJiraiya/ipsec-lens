# Security source review

Scope: repository-owned Python/TypeScript, dependencies and CI configuration. Local prototype threat model.
Review date: 2026-09-08. This is an internal engineering review, not an independent audit.

| Boundary | Implementation and review outcome |
|---|---|
| Upload body | Actual-byte middleware bound before multipart; 1 MiB spool threshold; two concurrent writes; idle timeout |
| Capture records | Fixed header checks, packet count, allocation, flow and payload-chain ceilings |
| Paths | Sanitized display basename; UUID paths; no client directory access; temporary directories |
| Cleanup | finally closes upload, context removes working files; capture retained only by explicit option |
| Telemetry | 2 MiB JSON, typed allowlist, capture hash and exact directional SPI match; unknown fields rejected |
| Sensitive data | Raw XFRM/key import unsupported; validation responses omit submitted values |
| Serialization | Fixed trusted JSON model, SHA check; no user-supplied pickle/joblib |
| Subprocess | Explicit local CLI only, argument arrays, no shell interpolation; local interface allowlist |
| Privilege | Non-root web runtime; optional capture/lab requires explicit local CLI actions |
| API exposure | Loopback defaults, Host allowlist, Origin checks for writes, no permissive CORS |
| Database | Parameterized SQLAlchemy operations, scoped sessions, transactions, WAL and revision checks |
| Frontend | React text escaping, no dangerous HTML insertion, abort/ticket handling for stale responses |
| Reports | HTML escaping, no external resources/scripts, CSP and nosniff response header |
| Testbed | Docker internal network, no host network/ports, generated random PSKs in ignored files |
| Offline | No network clients or remote assets in runtime analysis path |
| Dependencies | Pinned Python set and npm lock; npm install audit reported zero vulnerabilities at build time |

## Defects corrected during development

- Closed the hashing input file deterministically.
- Bounded aggregate retained transforms in addition to message and payload bounds.
- Added generic validation errors so submitted values are not reflected.
- Added Host validation and write Origin checks.
- Added upload idle timeout; capture ceiling remains separate from multipart overhead.
- Added frontend selection clearing and short-viewport scrollable navigation.
- Strengthened dataset identity to hash actual generated feature rows.
- Promoted synthetic telemetry provenance to a visible dashboard banner.
- Added typed checks and corrected integer/string variable reuse found by mypy.

## Adversarial regression coverage

Malformed/truncated captures, unsupported format, allocation/count ceilings, randomized bounded parser inputs,
structured IKE mutations, invalid JSON, unexpected secret field, path traversal and unsafe names,
oversized capture/body, rejected cross-origin writes, mismatched telemetry identity,
revision conflict, HTML injection escaping, UNKNOWN semantics, no IKE-to-ESP copying and abstention.

## Residual risks

Loopback is not authentication; same-user local clients can operate the API. Do not expose it publicly.
Telemetry is not signed or attested. A capture can be forged; checksums and cryptographic integrity are not verified.
Process crash may leave temporary files. System-wide disk exhaustion, per-user quotas and scheduled deletion
are not implemented. Upload timeout is per idle read, not a total request deadline.
Bounded randomized tests are not an exhaustive fuzzer campaign.
Installed dependency transitive code was not independently audited.
SHA-256 model checking assumes a trusted local installation.
Docker integration remains unverified; no privileged lab experiment was falsely reported successful.
