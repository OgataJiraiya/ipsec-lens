# Five-minute demonstration

## Prepare (before the timed demonstration)

    make install
    make demo
    make backend

Second terminal:

    make frontend

Open http://127.0.0.1:5173. The demo history already contains generated scenarios.
Use uploads below to show the real intake pipeline. Optional labels should include SYNTHETIC FIXTURE.

## 0:00–1:10 — Strong scenario

1. Click New Analysis.
2. Browse demo/strong/strong.pcap. Show filename, size and calculated SHA-256.
3. Select demo/strong/telemetry.json in the telemetry field. Keep MODERN and retention off.
4. Click Run analysis. Show security 97.5, risk 2.5, coverage 100%, AVAILABLE, ACCEPT.
5. Explain: this is a generated demonstration, and configuration is an ASSISTED assertion.
   ACCEPT is not a safety certificate.
6. Click Protocol Analysis. Show IKEv2/IKE_SA_INIT, AES-GCM-16, key length 256 and ECP384.
   Say: “These are visible IKE proposals; ESP configuration comes from separate telemetry.”

## 1:10–2:15 — Weak scenario

1. New Analysis → demo/weak/weak.pcap and demo/weak/telemetry.json → Run analysis.
2. Show 30.5 security, 69.5 risk, HARDEN.
3. Open Findings; choose HIGH. Show weak DH, PFS disabled and replay protection disabled.
4. Open Security Associations: show duplicate/regression/gap counters.
   Say: “Passive anomalies do not prove that an endpoint accepted a replay.”

## 2:15–3:00 — Traffic inference

1. Open Encrypted Traffic AI. Inspect class, confidence, probabilities and feature summary.
2. Say: “Encrypted payload was not decrypted. Classification is based on flow metadata.”
3. Explain that the model was trained on synthetic profiles, has no WhatsApp attribution,
   and its confidence is neither attack probability nor measured real-world accuracy.

## 3:00–3:40 — Matrix and reports

1. Open Threat Matrix. Review evidence, status, severity and confidence.
2. Reports → Download technical HTML. Open the downloaded file in a browser.
3. Show evidence provenance, score breakdown, limitations and configuration hardening.
4. Say: “This is a RECOMMENDATION. No VPN configuration is applied.”

## 3:40–4:40 — Unknown handling

1. New Analysis → demo/partial/partial.pcap, without telemetry → Run analysis.
2. Show 5% coverage, UNAVAILABLE score, REVIEW; not a fake secure score.
3. Security Associations: mode, crypto, PFS and replay window all UNKNOWN.
4. Optionally select replay demo (20% coverage) or IPv6 demo (73.3% coverage, PROVISIONAL)
   from the history selector.
5. Finish: “No finding does not mean safe. Missing evidence never becomes secure evidence.”

Expected fixture outcomes are verified by make demo and backend regression tests.
The optional strongSwan testbed must not be called LIVE unless independently started and verified.
