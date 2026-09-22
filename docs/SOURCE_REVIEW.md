# Historical offline source review (superseded)

This records the earlier offline baseline. Current results are in FINAL_SOURCE_REVIEW.md,
EXTERNAL_RELEASE_AUDIT.md and RELEASE_CHECKLIST.md; historical gaps below are not current release claims.

# Final source review

Reviewed repository-owned protocol code, schemas, feature extraction, inference, policy/coverage,
normalized telemetry, API, persistence, reports, frontend, testbed generation, CLI utilities, tests,
dependency manifests, CI and documentation against the original evidence constraints.

## Protocol and assessment checks

- IKE_SA_INIT transforms retain IKE proposal scope. Cleartext payloads outside that exchange are unverified.
- SK/SKF traversal stops without interpreting ciphertext as a payload chain.
- Unknown IDs remain numeric. Header identification does not claim authenticated negotiation.
- Native and NAT-T ESP use the same directional statistics. NAT-T itself is informational.
- PFS, mode, configured lifetime, ESN, replay-window and Child-SA algorithms are unknown until assisted.
- Impossible AES key lengths and contradictory AEAD/PFS telemetry are now rejected.
- Short GCM authentication tags receive explicit review rather than maximal crypto credit.
- Per-SA expected checks prevent selective telemetry from hiding unknown flows.
- Partial parsing halves visibility coverage. No unobserved field contributes secure credit.
- Sequence gaps remain informational, distinct from duplicates/regressions and endpoint replay policy.
- HIGH findings override high aggregate scores. ACCEPT is explicitly not certification.
- Synthetic fixture generation feeds the actual analyzer; numeric expected results exist only as test assertions.

## ML checks

- One feature row per independent synthetic session; group IDs and labels excluded from features.
- Train/validation/test groups disjoint; candidate selection uses validation only.
- Dataset hash covers actual generated feature rows, not only seed manifest.
- Exact model-byte reproducibility tested twice using the pinned environment.
- Fixed trusted JSON traversal, no user model path/deserialization.
- Seven synthetic labels, explicit non-claims, minimum sample count and threshold abstention.
- No real-world claim inferred from perfect synthetic metrics.

## Web/product checks

- Actual body/capture limits, bounded spooling, idle timeout and concurrency limit.
- Request validation does not echo sensitive submitted values.
- Generated capture paths, safe cleanup, retention opt-in and capture-bound telemetry.
- Demo cleanup now checks both fixture hashes and demo labels; unrelated captures are preserved.
- React escaping and escaped reports; report downloads verified as new files.
- Stale selected-analysis responses ignored; pending telemetry reads disable submission.
- Source badges/unknowns/provisional status visible; synthetic telemetry banner prominent.
- Narrow screens tested; navigation scrolling fixes short-viewport footer overlap.
- CDN-dependent automatic API documentation pages disabled; OpenAPI JSON remains available offline.

## Pattern search

No TODO, FIXME, NotImplemented, shell=True, eval(, exec(, pickle.load, joblib.load,
absolute developer path or API token in repository-owned production code.
Matches for placeholder are legitimate HTML input attributes/browser selectors.
Matches for mock are Vitest network/digest test doubles only.
The private_key match is a rejection test containing an inert sentinel, not a secret.
The word fake appears in a documented non-claim, not in analyzer behavior.
Python pass occurs in the SQLAlchemy declarative base and expected exception handling in bounded fuzz tests.
read_bytes/read_text calls are fixed model files with a size check, bounded/validated fixture inputs,
small local metadata, test helpers or local CLI inputs. The upload path streams fixed-size chunks.

## Remaining limits

The review does not establish real-world classifier accuracy, authenticated endpoint truth,
full IPsec conformance or live strongSwan interoperability. Docker permissions blocked the latter.
Raw swanctl/XFRM parsers, reassembly, server PDF and operational authentication remain documented gaps.
No remote CI run or independent security audit is claimed.
