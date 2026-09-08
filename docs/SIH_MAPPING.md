# SIH 26160 requirement mapping

COMPLETE — LIVE VERIFIED means exercised with actual isolated strongSwan SAs/captures.
COMPLETE — OFFLINE VERIFIED means tested implementation within documented scope.
Synthetic tests do not verify an actual VPN deployment. PARTIAL identifies absent integration/evidence.

| Requirement | Implementation | Evidence | Status |
|---|---|---|---|
| Capture ingestion | PCAP / PCAPNG enhanced packets | protocol/API tests, browser uploads | COMPLETE — OFFLINE VERIFIED |
| Local live capture | Bounded tcpdump sensor | live duration/byte limit/SIGINT cleanup | COMPLETE — LIVE VERIFIED |
| IKE detection/version | IKEv1/v2 headers | protocol regressions | COMPLETE — OFFLINE VERIFIED |
| IKEv2 transforms | Visible proposals, numeric unknowns, KE/attributes | transform/opaque-payload tests | COMPLETE — OFFLINE VERIFIED |
| IKEv1 detailed analysis | Header identification only | source/docs | PARTIAL |
| ESP native | Directional SPI and sequence statistics | fixtures/tests and real capture cross-check | COMPLETE — LIVE VERIFIED |
| NAT-T | Marker separation, ESP-in-UDP, keepalive | IPv6/weak tests and real capture cross-check | COMPLETE — LIVE VERIFIED |
| AH | Header/SPI/sequence/next-header only | IPv6 fixture | PARTIAL |
| IPv4 | Outer decoding; no fragment reassembly | tests | COMPLETE — OFFLINE VERIFIED |
| IPv6 | Ordinary live IPv6; common extensions offline only | live capture plus bounded parser tests | COMPLETE — LIVE VERIFIED |
| Tunnel / Transport | Unknown by default, normalized telemetry import | evidence tests and real capture cross-check | COMPLETE — LIVE VERIFIED |
| Tunnel / Transport live VPN | Isolated namespace SAs | LIVE_PROTOCOL_VALIDATION.json | COMPLETE — LIVE VERIFIED |
| AES128 / AES256 | IKE IDs/key bits; telemetry; lab profiles | tests/config generator | COMPLETE — LIVE VERIFIED |
| CBC + HMAC / GCM | Proposal maps, explicit scoring and profiles | tests/demos | COMPLETE — LIVE VERIFIED |
| DH groups | MODP/ECP/Curve maps and profile review | weak/strong tests | COMPLETE — OFFLINE VERIFIED |
| PFS | ASSISTED policy field, UNKNOWN otherwise | semantic tests | COMPLETE — OFFLINE VERIFIED |
| PFS live verification | list-conns plus actual Child rekey DH | raw endpoint samples and regression tests | COMPLETE — LIVE VERIFIED |
| SA characteristics | Directional count/time/volume/range | sequence tests | COMPLETE — OFFLINE VERIFIED |
| SA lifetime | Configured vs observed separated | policy/unknown tests and real capture cross-check | COMPLETE — LIVE VERIFIED |
| Replay protection | Reported replay window separate from signals | tests and real capture cross-check | COMPLETE — LIVE VERIFIED |
| Replay anomaly | Duplicate/regression/gap signals | replay demo | COMPLETE — OFFLINE VERIFIED |
| Crypto strength | Documented deterministic prototype policies | strong/weak/policy tests | COMPLETE — OFFLINE VERIFIED |
| Compliance | Profile evaluation, no external certification | policy docs | PARTIAL |
| Authentication | Visible integrity transforms; no peer auth verification | parser/policy | PARTIAL |
| Metadata exposure | Endpoints/timing/sizes/SPI/NAT visibility | findings/reports | COMPLETE — OFFLINE VERIFIED |
| Traffic feature extraction | 22 directional features, bidirectional helper | ML tests | COMPLETE — OFFLINE VERIFIED |
| Traffic prediction | Preserved synthetic model; experimental real/mixed RF | REAL_ML_EVALUATION.json; preliminary only | COMPLETE — LIVE VERIFIED |
| Real application / WhatsApp attribution | Deliberately unclaimed | no legitimate real dataset | NOT IMPLEMENTED |
| Real labelled traffic dataset | 120 real encrypted generated-workload captures | real_testbed manifest, five classes | COMPLETE — LIVE VERIFIED |
| Dataset split | Disjoint synthetic session/config groups | split-integrity tests | COMPLETE — OFFLINE VERIFIED |
| Training/evaluation | Three candidates, held-out test, metrics/hash | deterministic repeated training | COMPLETE — OFFLINE VERIFIED |
| AI confidence | Uncalibrated probability with caveats | UI/model card | COMPLETE — OFFLINE VERIFIED |
| Calibrated real-world confidence | Not established | model card | NOT IMPLEMENTED |
| Security/risk score | Weighted known-domain scoring | score tests | COMPLETE — OFFLINE VERIFIED |
| Assessment coverage | Per-SA unknown checks, partial visibility cap | tests | COMPLETE — OFFLINE VERIFIED |
| Threat matrix | Backend evidence/unknown rows | UI/reports | COMPLETE — OFFLINE VERIFIED |
| Executive report | Escaped standalone HTML | API/browser downloads | COMPLETE — OFFLINE VERIFIED |
| Technical report | Full evidence document | API/browser downloads | COMPLETE — OFFLINE VERIFIED |
| Server PDF | Bounded WeasyPrint, no URL fetching | API tests and browser downloads | COMPLETE — OFFLINE VERIFIED |
| Interactive dashboard | Eleven React views | Vitest/browser walkthrough | COMPLETE — OFFLINE VERIFIED |
| Configuration hardener | Recommendation-only policy fragment | API/report/UI | COMPLETE — OFFLINE VERIFIED |
| Strong/weak/replay/partial demos | Synthetic capture + actual pipeline | make demo | COMPLETE — OFFLINE VERIFIED |
| IPv6 demo | NAT-T ESP + basic AH, partial coverage | make demo | COMPLETE — OFFLINE VERIFIED |
| Isolated strongSwan integration | User/network/mount namespace fallback | real SAs, local ping/HTTP, tshark | COMPLETE — LIVE VERIFIED |
| Offline runtime | Local assets/model/database | browser/source review | COMPLETE — OFFLINE VERIFIED |
| Regressions | Python, frontend, browser, bounded fuzz | release results | COMPLETE — OFFLINE VERIFIED |
| CI | Workflow implemented; not pushed/run remotely | local equivalent gates | PARTIAL |
| Documentation | Architecture/semantics/model/demo/review/mapping | repository documents | COMPLETE — OFFLINE VERIFIED |

Live scope is narrow: forced ESP-in-UDP, ordinary IPv6, strong/weak tunnel and transport profiles. Docker execution, NAT router traversal, other generated crypto combinations and organic application attribution are not validated. See LIVE_VALIDATION.md.
