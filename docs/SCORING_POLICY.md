# Scoring and policy

This is an explicit prototype policy rubric, not an external compliance certification.

| Domain | Weight | Checks |
|---|---:|---|
| Cryptography | 25% | One matched Child-SA cipher/key-size/integrity evaluation per SA |
| Key Exchange | 20% | One reported Child-SA DH group per SA |
| PFS / Rekey | 20% | PFS and configured lifetime, separately for each SA |
| Replay Protection | 15% | Reported configured replay window per SA |
| Protocol Hygiene | 15% | Observed IKE version |
| Metadata Exposure | 5% | Presence of visible ESP metadata |

Unknown checks have no score. Domain coverage = known checks / expected checks.
Domain score = average of known check values. Every SA contributes expected checks, including unknown SAs.
Basic AH currently uses the same conservative expected configuration set, so it can lower coverage;
AH-specific non-applicable encryption handling is a future refinement.

Overall coverage = sum(domain weight × domain coverage).
Overall security score = sum(score × weight × coverage) / sum(weight × coverage), if coverage >= 0.50.
Risk = 100 − security score, only if score is shown.
Coverage below 0.50 → UNAVAILABLE/null. Partial coverage → PROVISIONAL.
All checks known → AVAILABLE. These statuses never claim full capture authenticity or cryptographic validation.
Known parser/retention visibility loss halves coverage and forces a partial assessment.

## Rubric

AEAD meeting key preference: 100. 3DES or unauthenticated CBC/CTR: 0.
CBC/CTR + SHA2: 90 in COMPATIBILITY, 75 otherwise; it is not automatically broken.
CBC/CTR + HMAC-SHA1: 40. AES key below profile preference caps crypto at 60.
Unknown integrity for a non-AEAD cipher leaves crypto unknown. Unknown AES key size leaves crypto unknown.
DH 0/1/2/5: 0; approved groups: 100; known other groups: 60; unmapped groups: unknown.
PFS enabled: 100; disabled: 0. Missing PFS: unknown.
Reasonable positive lifetime: 100; zero/unlimited or excessive: 30; missing: unknown.
Replay window positive: 100; zero: 0; missing: unknown.
IKEv2 observed: 100; any IKEv1: 30; neither: unknown.
ESP metadata visible: 50 under the exposure rubric, not a claim that encryption is broken.

| Profile | AES preference | Approved DH groups | Maximum configured lifetime |
|---|---|---|---|
| MODERN | 256 bit, AEAD preferred | 19,20,21,31,32 | 3600 s |
| COMPATIBILITY | 128+ bit; CBC/SHA2 allowed | 14–21,31,32 | 14400 s |
| STRICT | 256 bit, AEAD preferred | 20,21,32 | 1800 s |

A strong AEAD configuration therefore scores 97.5 rather than 100 because metadata remains exposed.
Values are policy choices centralized in core/security_policy.py and services/policy.py.

## Findings and disposition

Visible weak IKE proposals produce findings, without pretending they are selected ESP algorithms.
HIGH findings force HARDEN; CRITICAL forces QUARANTINE. No current rule invents a critical attack.
Partial evidence or LOW/MEDIUM findings yields REVIEW. Otherwise ACCEPT is a limited policy disposition,
never SAFE or a certificate. Informational metadata/NAT-T observations do not imply insecurity.
Sequence anomaly evidence confidence refers to observation reliability, not probability of an attack.

Threat matrix rows derive from backend findings and explicit unknown configuration checks.
Configuration hardener outputs policy-specific ipsec.conf-style fragments labelled RECOMMENDATION.
No configuration is applied, no host commands run.
