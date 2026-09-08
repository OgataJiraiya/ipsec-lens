"""Evidence-aware domain scoring. Unknown checks receive no secure credit."""
import hashlib
from typing import Literal
from backend.schemas.models import Recommendation
from backend.core.security_policy import POLICIES, DOMAIN_WEIGHTS
from backend.protocol.ike import ALGORITHMS
from backend.schemas.models import Finding, Source, Domain, Score, ThreatRow


def assess(summary, sas, policy_name, visibility_partial=False):
    policy = POLICIES[policy_name]
    findings = []

    def add(category, severity, source, reason, evidence, remediation, confidence=1.0,
            recommendation="HARDEN", limitations=None):
        identity = category + "|" + "|".join(evidence)
        findings.append(Finding(finding_id="IPSEC-F-" + hashlib.sha256(identity.encode()).hexdigest()[:10],
            category=category, severity=severity, source=source, reason=reason, evidence=evidence,
            confidence=confidence, recommendation=recommendation, remediation=remediation,
            limitations=limitations or []))

    checks: dict[str, list[tuple[float | None, str]]] = {name: [] for name in DOMAIN_WEIGHTS}

    def check(domain, score, evidence):
        checks[domain].append((score, evidence))

    # Offered IKE algorithms are observable, but are not proof of selected/established algorithms.
    for msg in summary.ike_messages:
        for t in msg.transforms:
            evidence = [f"IKE message={msg.message_id}; endpoints={msg.src}->{msg.dst}",
                        f"scope={t.scope}; proposal={t.proposal}; protocol_id={t.protocol_id}",
                        f"transform={t.transform_type}:{t.transform_id}; name={t.name}"]
            limitation = ["A visible proposal is not proof of negotiated use or ESP Child-SA transforms."]
            if t.name == "3DES":
                add("WEAK_ENCRYPTION", "HIGH", Source.OBSERVED, "3DES appears in a visible proposal.",
                    evidence, "Remove 3DES from proposals.", limitations=limitation)
            if t.transform_type == 4:
                if t.transform_id in (0, 1, 2, 5):
                    add("WEAK_DH_GROUP", "HIGH", Source.OBSERVED, f"{t.name} appears in a visible proposal.",
                        evidence, "Use an approved ECDH group.", limitations=limitation)
                elif t.transform_id not in policy.dh_groups:
                    add("DH_POLICY_REVIEW", "MEDIUM", Source.OBSERVED, "DH group outside selected policy preference.",
                        evidence, "Review interoperability and policy-approved groups.", limitations=limitation)
            if "SHA1" in t.name:
                add("SHA1_POLICY", "MEDIUM", Source.OBSERVED, "SHA-1-based transform offered.",
                    evidence, "Prefer SHA-2-based PRF/integrity. HMAC-SHA1 is distinct from SHA-1 signatures.",
                    limitations=limitation)
            if t.name == "AES-CBC":
                add("CBC_POLICY", "INFO" if policy.allow_cbc_sha2 else "LOW", Source.OBSERVED,
                    "AES-CBC is offered; integrity pairing and selection require review.", evidence,
                    "CBC is not automatically broken. Prefer AEAD or verify strong integrity pairing.",
                    recommendation="REVIEW", limitations=limitation)
            if t.name.startswith("UNKNOWN"):
                add("UNKNOWN_TRANSFORM", "LOW", Source.OBSERVED, "Unmapped transform preserved numerically.",
                    evidence, "Resolve the IANA/vendor identifier before evaluating it.", recommendation="REVIEW")
    # One check per SA and property prevents a single known SA hiding other unknown SAs.
    for sa in sas:
        ref = f"SA={sa.sa_id}; SPI={sa.spi}"
        enc, bits, integrity = sa.encryption_algorithm.value, sa.encryption_key_bits.value, sa.integrity_algorithm.value
        crypto = None
        if enc == "3DES":
            crypto = 0
            add("WEAK_ENCRYPTION", "HIGH", Source.ASSISTED, "Endpoint telemetry reports 3DES.",
                [ref, "encryption=3DES"], "Replace with policy-approved AEAD.", .9)
        elif enc and (str(enc).startswith("AES") or enc == "CHACHA20-POLY1305"):
            if str(enc).startswith("AES") and bits is None:
                crypto = None
            elif enc in ("AES-CBC", "AES-CTR") and integrity is None:
                crypto = None
            else:
                crypto = 100
                if str(enc).startswith("AES") and int(bits or 0) < policy.minimum_aes_bits:
                    crypto = min(crypto, 60)
                    add("KEY_LENGTH_POLICY", "MEDIUM", Source.ASSISTED, "AES key length below policy preference.",
                        [ref, f"key_bits={bits}"], "Use policy-approved key length.", .9)
                if enc in ("AES-CBC", "AES-CTR"):
                    if integrity == "NONE":
                        crypto = 0
                        add("MISSING_INTEGRITY", "HIGH", Source.ASSISTED,
                            "Non-AEAD ESP has no reported integrity protection.", [ref, f"encryption={enc}", "integrity=NONE"],
                            "Enable authenticated encryption or strong ESP integrity.", .9)
                    elif integrity and integrity.startswith("HMAC-SHA2"):
                        crypto = min(crypto, 90 if policy.allow_cbc_sha2 else 75)
                    elif integrity == "HMAC-SHA1-96":
                        crypto = min(crypto, 40)
                        add("SHA1_POLICY", "MEDIUM", Source.ASSISTED, "Endpoint reports SHA-1-based integrity.",
                            [ref, f"integrity={integrity}"], "Prefer HMAC-SHA2 or AEAD.", .9)
                    else:
                        crypto = None
                    add("CBC_CTR_POLICY", "INFO" if policy.allow_cbc_sha2 else "LOW", Source.ASSISTED,
                        "Non-AEAD encryption requires integrity and policy review.", [ref, f"encryption={enc}"],
                        "Use AEAD where possible; CBC with strong integrity is permitted by COMPATIBILITY.",
                        .9, "REVIEW")
        check("Cryptography", crypto, f"{ref}; Child-SA crypto={enc}; bits={bits}; integrity={integrity}")
        dh = sa.dh_group.value
        dhscore = None if dh is None or dh not in ALGORITHMS[4] else (
            0 if dh in (0, 1, 2, 5) else 100 if dh in policy.dh_groups else 60)
        check("Key Exchange", dhscore, f"{ref}; endpoint Child-SA DH={dh}")
        if dhscore is not None and dhscore < 100:
            add("WEAK_DH_GROUP" if dhscore == 0 else "DH_POLICY_REVIEW",
                "HIGH" if dhscore == 0 else "MEDIUM", Source.ASSISTED,
                "Endpoint DH does not meet selected policy.", [ref, f"dh_group={dh}"],
                "Use a policy-approved DH group.", .9)
        pfs, lifetime, window = sa.pfs_enabled.value, sa.configured_lifetime.value, sa.replay_window.value
        check("PFS / Rekey", None if pfs is None else 100 if pfs else 0, f"{ref}; configured PFS={pfs}")
        check("PFS / Rekey", None if lifetime is None else 100 if 0 < lifetime <= policy.max_lifetime else 30,
              f"{ref}; configured lifetime={lifetime}")
        if pfs is False:
            add("PFS_DISABLED", "HIGH", Source.ASSISTED, "Telemetry reports configured PFS disabled.",
                [ref, "pfs_enabled=false"], "Enable fresh DH for Child-SA rekeys.", .9)
        if lifetime is not None and (lifetime == 0 or lifetime > policy.max_lifetime):
            add("LONG_SA_LIFETIME", "MEDIUM", Source.ASSISTED, "Configured lifetime exceeds policy or is unlimited.",
                [ref, f"configured_lifetime={lifetime}"], f"Use a lifetime at most {policy.max_lifetime} seconds.", .9)
        check("Replay Protection", None if window is None else 100 if window > 0 else 0,
              f"{ref}; configured replay window={window}")
        if window == 0:
            add("REPLAY_PROTECTION_DISABLED", "HIGH", Source.ASSISTED, "Telemetry reports a zero replay window.",
                [ref, "replay_window=0"], "Enable endpoint anti-replay protection.", .9)
        for category, amount, severity in [
            ("ESP_DUPLICATE_SEQUENCE", sa.replay_signals.duplicates, "MEDIUM"),
            ("ESP_SEQUENCE_REGRESSION", sa.replay_signals.regressions, "MEDIUM"),
            ("ESP_SEQUENCE_GAP", sa.replay_signals.large_gaps, "INFO"),
            ("ESP_ZERO_SEQUENCE", sa.replay_signals.zero_sequences, "LOW"),
        ]:
            if amount:
                add(category.replace("ESP", sa.protocol), severity, Source.DERIVED,
                    "Passive sequence anomaly observed; endpoint replay acceptance is unknown.",
                    [ref, f"count={amount}"], "Correlate capture location, packet loss/reordering, ESN and endpoint counters.",
                    .95, "REVIEW", ["Sequence gaps alone are not replay attacks.",
                                   "Duplicate/regressing packets may originate from capture artifacts."])
    if not sas:
        for name in ("Cryptography", "Key Exchange", "PFS / Rekey", "Replay Protection"):
            check(name, None, "No matching SA telemetry")
    ike_versions = {m.version for m in summary.ike_messages}
    check("Protocol Hygiene", 30 if "IKEv1" in ike_versions else 100 if "IKEv2" in ike_versions else None,
          "Observed IKE versions: " + ", ".join(sorted(ike_versions)))
    if "IKEv1" in ike_versions:
        add("IKEV1", "MEDIUM", Source.OBSERVED, "IKEv1 identified.", ["IKEv1 header"],
            "Migrate to IKEv2 after interoperability review.")
    esp_count = summary.counts.get("ESP", 0)
    # Fixed exposure score is an explicit policy rubric for visible metadata, not encryption failure.
    check("Metadata Exposure", 50 if esp_count else None, "ESP outer metadata visibility" if esp_count else "No ESP")
    if esp_count:
        add("METADATA_EXPOSURE", "INFO", Source.OBSERVED,
            "ESP hides payload but exposes endpoints, sizes, timing, volume and SPI.",
            [f"ESP packets={esp_count}"], "Evaluate padding, aggregation and traffic-flow confidentiality needs.",
            recommendation="REVIEW")
    if summary.counts.get("NAT_T"):
        add("NAT_T", "INFO", Source.OBSERVED, "UDP/4500 encapsulation observed; NAT-T is not inherently insecure.",
            [f"NAT-T packets={summary.counts['NAT_T']}"], "Maintain appropriate NAT mappings and endpoint policy.",
            recommendation="REVIEW")
    for version in ("IPv4", "IPv6"):
        if summary.counts.get(version):
            add("IP_VERSION_POSTURE", "INFO", Source.OBSERVED, f"{version} outer headers observed.",
                [f"{version} packets={summary.counts[version]}"], "Review corresponding firewall and IPsec selectors.",
                recommendation="REVIEW")
    domains = []
    for name, entries in checks.items():
        known = [s for s, _ in entries if s is not None]
        coverage = len(known) / len(entries) if entries else 0
        if visibility_partial:
            coverage *= .5  # Explicit conservative cap when parsing or retention reduced visibility.
        domains.append(Domain(name=name, score=sum(known) / len(known) if known else None,
                              weight=DOMAIN_WEIGHTS[name], coverage=coverage,
                              evidence=[e for _, e in entries]))
    coverage = sum(d.weight * d.coverage for d in domains)
    available_weight = sum(d.weight * d.coverage for d in domains if d.score is not None)
    score_value = (round(sum(d.score * d.weight * d.coverage for d in domains if d.score is not None)
                         / available_weight, 1) if coverage >= .5 and available_weight else None)
    status: Literal["AVAILABLE", "PROVISIONAL", "UNAVAILABLE"] = "UNAVAILABLE" if score_value is None else "AVAILABLE" if coverage >= .999999 else "PROVISIONAL"
    if coverage < .999999:
        add("INSUFFICIENT_EVIDENCE", "LOW", Source.UNKNOWN, "Some assessment domains lack sufficient evidence.",
            [f"coverage={coverage:.3f}"], "Import capture-matched endpoint telemetry and a complete negotiation capture.",
            0, "REVIEW")
    disposition: Recommendation = ("QUARANTINE" if any(f.severity == "CRITICAL" for f in findings) else
                   "HARDEN" if any(f.severity == "HIGH" for f in findings) else
                   "REVIEW" if status != "AVAILABLE" or any(f.severity in ("MEDIUM", "LOW") for f in findings) else "ACCEPT")
    score = Score(security_score=score_value, risk_score=round(100 - score_value, 1) if score_value is not None else None,
                  assessment_coverage=round(coverage, 6), score_status=status, overall_disposition=disposition,
                  domains=domains)
    # Deduplicate repeated proposal findings without discarding separate SA evidence.
    findings = list({f.finding_id: f for f in findings}.values())
    rows = [ThreatRow(threat=f.category, evidence=f.evidence,
                      status="UNKNOWN" if f.source == Source.UNKNOWN else "REVIEW" if f.severity == "INFO" else "DETECTED",
                      severity=f.severity, confidence=f.confidence, impact=f.reason, recommendation=f.remediation)
            for f in findings]
    for name, field in [("Unknown Child-SA Crypto", "encryption_algorithm"), ("No PFS", "pfs_enabled"),
                        ("Long Lifetime", "configured_lifetime"), ("Replay Protection Disabled", "replay_window")]:
        if not sas or any(getattr(sa, field).value is None for sa in sas):
            rows.append(ThreatRow(threat=name, evidence=["Missing matched endpoint evidence"], status="UNKNOWN",
                                  severity="INFO", confidence=0, impact="Cannot evaluate this property.",
                                  recommendation="Import normalized endpoint telemetry."))
    return findings, score, rows
