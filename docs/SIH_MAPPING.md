# SIH 26160 requirement mapping

COMPLETE means the described implementation is working within its documented prototype scope.
Synthetic tests do not verify an actual VPN deployment. PARTIAL identifies absent integration/evidence.

| Requirement | Implementation | Evidence | Status |
|---|---|---|---|
| Capture ingestion | PCAP / PCAPNG enhanced packets | protocol/API tests, browser uploads | COMPLETE |
| Local live capture | tcpdump CLI, bounded duration, local interface validation | source review; no privileged capture run | PARTIAL |
| IKE detection/version | IKEv1/v2 headers | protocol regressions | COMPLETE |
| IKEv2 transforms | Visible proposals, numeric unknowns, KE/attributes | transform/opaque-payload tests | COMPLETE |
| IKEv1 detailed analysis | Header identification only | source/docs | PARTIAL |
| ESP native | Directional SPI and sequence statistics | fixtures/tests | COMPLETE |
| NAT-T | Marker separation, ESP-in-UDP, keepalive | IPv6/weak tests | COMPLETE |
| AH | Header/SPI/sequence/next-header only | IPv6 fixture | PARTIAL |
| IPv4 | Outer decoding; no fragment reassembly | tests | COMPLETE |
| IPv6 | Common extensions; unsupported chains explicit | tests and demo | PARTIAL |
| Tunnel / Transport | Unknown by default, normalized telemetry import | evidence tests | COMPLETE |
| Tunnel / Transport live VPN | strongSwan generator | daemon permission denied | PARTIAL |
| AES128 / AES256 | IKE IDs/key bits; telemetry; lab profiles | tests/config generator | COMPLETE |
| CBC + HMAC / GCM | Proposal maps, explicit scoring and profiles | tests/demos | COMPLETE |
| DH groups | MODP/ECP/Curve maps and profile review | weak/strong tests | COMPLETE |
| PFS | ASSISTED policy field, UNKNOWN otherwise | semantic tests | COMPLETE |
| PFS live verification | Generated rekey proposals | no established lab verification | PARTIAL |
| SA characteristics | Directional count/time/volume/range | sequence tests | COMPLETE |
| SA lifetime | Configured vs observed separated | policy/unknown tests | COMPLETE |
| Replay protection | Reported replay window separate from signals | tests | COMPLETE |
| Replay anomaly | Duplicate/regression/gap signals | replay demo | COMPLETE |
| Crypto strength | Documented deterministic prototype policies | strong/weak/policy tests | COMPLETE |
| Compliance | Profile evaluation, no external certification | policy docs | PARTIAL |
| Authentication | Visible integrity transforms; no peer auth verification | parser/policy | PARTIAL |
| Metadata exposure | Endpoints/timing/sizes/SPI/NAT visibility | findings/reports | COMPLETE |
| Traffic feature extraction | 22 directional features, bidirectional helper | ML tests | COMPLETE |
| Traffic prediction | Seven synthetic profiles; probabilities/abstention | training/browser/tests | COMPLETE |
| Real application / WhatsApp attribution | Deliberately unclaimed | no legitimate real dataset | NOT IMPLEMENTED |
| Real labelled traffic dataset | Synthetic fallback only | dataset manifests | PARTIAL |
| Dataset split | Disjoint synthetic session/config groups | split-integrity tests | COMPLETE |
| Training/evaluation | Three candidates, held-out test, metrics/hash | deterministic repeated training | COMPLETE |
| AI confidence | Uncalibrated probability with caveats | UI/model card | COMPLETE |
| Calibrated real-world confidence | Not established | model card | NOT IMPLEMENTED |
| Security/risk score | Weighted known-domain scoring | score tests | COMPLETE |
| Assessment coverage | Per-SA unknown checks, partial visibility cap | tests | COMPLETE |
| Threat matrix | Backend evidence/unknown rows | UI/reports | COMPLETE |
| Executive report | Escaped standalone HTML | API/browser downloads | COMPLETE |
| Technical report | Full evidence document | API/browser downloads | COMPLETE |
| Server PDF | Optional omitted | limitations | NOT IMPLEMENTED |
| Interactive dashboard | Eleven React views | Vitest/browser walkthrough | COMPLETE |
| Configuration hardener | Recommendation-only policy fragment | API/report/UI | COMPLETE |
| Strong/weak/replay/partial demos | Synthetic capture + actual pipeline | make demo | COMPLETE |
| IPv6 demo | NAT-T ESP + basic AH, partial coverage | make demo | COMPLETE |
| Isolated strongSwan integration | Compose and profiles provided | no daemon access | PARTIAL |
| Offline runtime | Local assets/model/database | browser/source review | COMPLETE |
| Regressions | Python, frontend, browser, bounded fuzz | release results | COMPLETE |
| CI | Workflow implemented; not pushed/run remotely | local equivalent gates | PARTIAL |
| Documentation | Architecture/semantics/model/demo/review/mapping | repository documents | COMPLETE |
