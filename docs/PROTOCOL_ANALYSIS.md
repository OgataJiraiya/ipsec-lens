# Protocol analysis and epistemic rules

Normative references:
- [RFC 7296: IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html), especially sections 1.2, 3.1–3.5 and 3.14.
- [RFC 4303: ESP](https://www.rfc-editor.org/rfc/rfc4303.html), especially sections 2 and 3.4.
- [IANA IKEv2 parameters](https://www.iana.org/assignments/ikev2-parameters/).

These references inform header decoding, transform identifiers and scope distinctions.
The analyzer is not a complete standards-conformance verifier.

## Capture and network decoding

Classic PCAP supports both byte orders, microsecond/nanosecond timestamps.
PCAPNG supports section/interface/enhanced-packet blocks, section byte-order resets, timestamp resolution
and timestamp offsets. Unknown bounded blocks are skipped; obsolete/simple packet blocks rejected.
Link types: Ethernet (1), raw IP (101), cooked v1 (113), raw IPv4/IPv6 (228/229), cooked v2 (276).
Up to four VLAN tags; IPv4 header/options lengths validated; fragments explicitly unsupported.
IPv6 hop-by-hop, routing, destination options and atomic fragments are traversed, up to 16 headers.
Non-atomic fragments require reassembly and are skipped. Mobility/HIP/Shim6 chains are unsupported.
Checksums, integrity tags and endpoint acceptance are not validated.

## IKE

UDP/500 carries candidate IKE; a valid 28-byte header is required.
UDP/4500 zero Non-ESP Marker selects IKE; nonzero SPI selects ESP; 0xff is NAT keepalive.
NAT-T presence is observational and does not imply vulnerability.

IKEv1: version/header identification, exchange numeric value, encryption flag; no v1 transform decoding.
IKEv2: initiator/responder SPI, version, exchange, flags, message ID, payload chain, proposal number,
protocol ID, transform type/ID, TV/TLV key-length attribute and KE group.
Known exchanges: IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL.
Known maps include 3DES, AES-CBC/CTR/GCM, ChaCha20-Poly1305, SHA1/SHA2 integrity and PRFs,
MODP groups, ECP groups and Curve25519/448. Unknown numeric IDs are preserved.

**IKE_SA_INIT exposes IKE SA proposals. It does not expose authenticated ESP Child-SA configuration.**
Offered algorithms need not be selected or used. Even response proposals are not proof of an
authenticated completed exchange. Cleartext SA payloads outside IKE_SA_INIT are marked unverified.
SK/SKF encrypted payloads stop visible traversal. Their next-payload field is not a visible continuation.
No decryption, encrypted fragment reassembly, exchange authentication or retransmission association.

## ESP and AH

ESP exposes outer endpoints, IP version, SPI, 32-bit sequence, timing and packet length.
Directional identity: (source, destination, protocol, SPI). SPI reuse over time may conflate SAs.
Statistics: count, bytes, first/last timestamps, observed duration, mean/std size, rate, sequence range.
Duplicate sequence counts are exact within the bounded capture; regressions compare adjacent capture order.
Large gaps exceed 1024 sequence positions. Additional SPIs at the same endpoint pair are possible SA changes,
not proven rekeys. Opposite-direction SPIs are not automatically paired.

**Passive anomalies do not establish replay acceptance or configured replay-window size.**
Capture duplication, reordering, packet loss, ESN wrap and SPI reuse are alternative explanations.
No successful anti-replay policy is inferred from an anomaly-free capture.

AH: validates basic header length and exposes next-header, SPI and sequence. Authentication is not verified,
and inner protocol recursion through AH is not implemented.

## Configuration certainty

All initially unknown SA configuration values carry null / UNKNOWN / confidence 0:
mode, ESP encryption/integrity/key bits, PFS policy, DH, configured lifetime, replay window, ESN, selectors.
Only matched normalized telemetry can populate these as ASSISTED. Confidence 0.9 reflects an operator assertion,
not cryptographic attestation. Outer passive ESP alone cannot distinguish tunnel and transport reliably.

Configured lifetime differs from observed duration. Configured PFS differs from proof of every rekey's DH.
Implementation, version and CVEs remain unknown without supporting endpoint evidence.

## Standards alignment / engineering references

Verified publisher references (2026-09-22):

| Reference | How it informs this prototype | Boundary |
|---|---|---|
| [RFC 7296, IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html), §§1.2, 3.1–3.4, 3.14 | Exchange/header/proposal/transform/KE interpretation; opaque encrypted payload boundary | No IKE AUTH cryptographic verification |
| [RFC 4303, ESP](https://www.rfc-editor.org/rfc/rfc4303.html), §§2, 3.4 | SPI/sequence visibility and receiver anti-replay distinction | Passive anomalies cannot prove receiver acceptance |
| [RFC 4302, AH](https://www.rfc-editor.org/rfc/rfc4302.html), §2 | Basic AH next-header, length, SPI and sequence interpretation | No authentication verification |
| [NIST SP 800-77 Rev. 1, Guide to IPsec VPNs](https://csrc.nist.gov/pubs/sp/800/77/r1/final) | Engineering context for IPsec VPN configuration, deployment and lifecycle review | Guidance, not an implemented conformance checklist |

These are engineering references, not certification or a claim of complete standards
compliance. Scoring remains the unchanged prototype rubric in SCORING_POLICY.md; no
weights or thresholds are attributed to these standards.
