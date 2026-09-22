# Architecture

Backend: Python 3.13, FastAPI, Pydantic v2, SQLAlchemy/SQLite, NumPy, pandas, scikit-learn training.
Frontend: React 19, TypeScript, Vite, lucide-react, CSS. No CDN fonts/assets or external runtime services.
Wire decoding uses Python stdlib deliberately: a small auditable parser for visible headers.

## Data path and ownership

1. ASGI intake middleware limits actual body bytes before multipart processing. Two concurrent writes maximum.
   It spools beyond 1 MiB and enforces a 30-second idle read timeout.
2. A synchronous worker streams UploadFile into a UUID-named temporary directory, with a separate capture ceiling.
3. SHA-256 identifies capture bytes. File-provided names are display-only sanitized basenames.
4. The reader yields timestamp, link type and bounded packet bytes. IP parsing precedes transport parsing.
5. IKE messages and directional ESP/AH flows produce typed observations.
6. Matching imported telemetry merges allowlisted properties as ASSISTED; no endpoint command execution.
7. The classifier reads a trusted fixed JSON model. Feature rows contain sizes and timing only.
8. Policy rules produce findings, domain checks, coverage and disposition. UI never creates findings.
9. SQLAlchemy commits a typed analysis document and indexed metadata in one transaction.
10. Reports derive from the persisted document and its revision. HTML escapes all dynamic content.

## Boundaries

Default upload: 256 MiB. Packet count: 1,000,000. Packet/block allocation: approximately 320 KiB.
Directional flows: 4096. Retained IKE messages: 4096. Aggregate retained transforms: 16384.
Per-message transform limit: 512. IPv6 extension loop: 16. IKE payload loop: 64.
Telemetry: 2 MiB and 4096 SA entries. Model JSON: 32 MiB. Classifier prefix: 2048 packets per flow.

A record boundary error rejects the analysis; malformed individual packets are counted/skipped and
mark analysis PARTIAL. Coverage is halved when decoding/retention has known visibility loss.
COMPLETE means the bounded analysis operation completed, not that all security properties are known.

## Persistence and concurrency

SQLite WAL, busy timeout, request-scoped sessions, transaction-scoped mutations.
Indexes: creation timestamp and capture hash; primary key analysis UUID.
Telemetry updates require expected_revision and use an optimistic SQL update.
Repeated captures are allowed as independent policy/telemetry assessments.
Default uploads are not retained; retained captures use generated IDs, never client paths.
HTML reports are generated from stored revision on demand; report routes are persisted references.

## Frontend state

Selection changes clear the previous analysis while loading. AbortController plus monotonic request
tickets discard old responses. File hashing has its own selection ticket. Backend errors render as text.
React escaping is retained; no raw HTML injection. Report links are built from fixed API routes.
Blank selection clears the loaded analysis. Evidence values always show UNKNOWN for null.

## Operating scope

Single-machine analyst workspace. No authentication, cloud, multi-tenancy or public deployment.
Loopback binding and Host/Origin checks reduce unintended browser access, but local operators remain trusted.

## Local lifecycle and comparison

`GET /api/analyses/{identity}/export` returns the persisted typed Analysis at its current
revision as an attachment (`application/json`, generated filename, `nosniff`). It does
not include retained capture bytes, raw endpoint key fields or internal storage paths.
Operator-entered labels/provenance remain part of the document; do not put secrets in them.

`DELETE /api/analyses/{identity}` accepts exactly 32 lowercase hexadecimal characters,
like detail/report endpoints. HTTP 200 returns DELETED or ALREADY_ABSENT; invalid IDs
return 404. DELETE has the same Host, Origin, body and concurrency limits as other writes.
A SQLite write transaction serializes deletion with telemetry updates. Only a row marked
retain_capture allows removal of `captures/<generated ID>.pcap`. Directory descriptors
opened with O_DIRECTORY/O_NOFOLLOW anchor unlink to configured local storage. Capture
symlinks and nonregular files are refused; no recursive deletion is exposed.

Capture cleanup failure returns 409 and rolls back DB deletion. Missing captures are
harmless on retry. Filesystem unlink and SQLite commit cannot be one atomic transaction:
a crash/commit failure after unlink can leave a row whose retained capture is absent.
Retry completes deletion; analysis/report data remain usable until then. This is logical
deletion, not forensic secure erasure of SQLite free pages/WAL, backups or downloaded reports.

Comparison loads two persisted documents independently with abort guards; selection changes
invalidate old content. Scores are right minus left, with UNKNOWN if either score is null.
Configuration compares only exact directional endpoint/protocol/SPI identities; absent SAs
are observation changes, not proven teardown/rekey. Unknown properties stay incomparable.
Findings use backend identity plus severity/source/reason. RESOLVED means absent from the
second snapshot, not verified remediation. Policy and coverage remain visible side-by-side.

Evidence Provenance preserves typed sources, including DERIVED sequence statistics rather
than relabelling them OBSERVED. Capture source is SYNTHETIC_FIXTURE only on a bundled
manifest hash match; otherwise UNVERIFIED. Old persisted documents default to UNVERIFIED.
No filename, analyst label or absence of synthetic telemetry establishes real capture origin.
