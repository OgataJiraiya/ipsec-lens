# Limitations and non-claims

- Bundled demo PCAPs remain synthetic. Real namespace captures of generated workloads were evaluated separately; no external deployment validation.
- Wire-format fixtures contain dummy KE values and opaque ESP bytes, not authenticated encryption.
- No decryption, password cracking, vulnerability reproduction, exploitation or external scanning.
- IKEv1 header identification only; no v1 proposal decoding.
- No authenticated negotiation verification, IKE/ESP association inference or endpoint version/CVE claims.
- IKE_SA_INIT proposal ≠ selected cipher ≠ ESP Child-SA transform.
- Encrypted IKE payloads remain opaque. No IKE fragmented-payload reassembly.
- AH is basic header recognition; no integrity verification or inner recursion.
- IPv4/IPv6 fragments are unsupported except atomic IPv6 fragments.
- PCAPNG simple/obsolete packet blocks, pcap gzip, unusual link types and IPv6 jumbograms are unsupported.
- No IP/UDP checksum or ESP authentication verification; a syntactically plausible forged capture can mislead.
- Directional (endpoints, protocol, SPI) grouping can conflate SPI reuse; one SA can multiplex applications.
- Sequence duplicates/regressions/gaps do not prove replay acceptance, replay-window policy or an attack.
- ESN high-order sequence tracking is not reconstructed.
- Telemetry is an operator assertion, not attested endpoint truth; collected_at is not automatically aligned
  to every capture timestamp. The capture hash binds intended association, not authenticity.
- Raw parsers support observed strongSwan 6.0.7/Linux formats, not every version. Raw XFRM contains keys: only sanitized samples are committed.
- Mode/PFS/lifetime/replay window unknown without matched telemetry.
- Scoring is a documented prototype rubric, not NTRO certification or an external compliance standard.
- No comprehensive score of IKE authentication (certificates/PSK strength), endpoint software or CVEs.
- Prefix classification, no automatic paired-SA model or real application attribution.
- No probability calibration; abstention cannot eliminate confident out-of-distribution errors.
- Synchronous bounded analysis with two concurrent writes; no job queue or cancellation/progress API.
- Non-root loopback backend only, no authentication/multi-user isolation; unsuitable for public exposure.
- HTML is canonical; offline PDF export has a 256 KiB HTML ceiling and one-render concurrency limit.
- Capture retention is opt-in; explicit per-analysis UI deletion is available; no retention scheduling. Deletion is not forensic erasure; downloaded reports, backups and SQLite free pages/WAL may retain data. Protect the local runtime directory.
- Graceful temporary cleanup is implemented; an OS kill/crash can leave spool/temp artifacts.
- Docker integration remains unverified due permissions. Real isolated namespace strong/weak, transport, IPv6 and forced NAT-T SAs are verified.
- Benchmark represents one synthetic directional flow, not worst-case many-SA/IKE-heavy workloads.

- Real ML validation is preliminary: generated workloads, one host/topology, five classes, four held-out tunnel groups. Production synthetic model transfers poorly (macro F1 0.32).
- Forced NAT-T is not a NAT-router traversal test; live IPv6 extension chains were not exercised.

- Comparison is snapshot evidence comparison, not a causal improvement or verified remediation claim. Different policies and visibility can change scores/findings. Exact directional SPI matching does not associate rekeys.
- Capture removal precedes DB commit: a crash/commit failure may leave a row with no retained capture; retry deletion. Symlink/nonregular capture storage fails closed.
