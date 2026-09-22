# Five-minute live demonstration

Prepare first: follow LIVE_VALIDATION.md, then start `make backend` and `make frontend`. Live captures and telemetry must already exist under runtime/live; no LIVE badge implies a currently running tunnel. Use the local dashboard URL printed by Vite.

1. **0:00 New Analysis:** choose runtime/live/strong/negotiation.pcap and optional telemetry.json from the same directory. Select MODERN and Run Analysis. These are real lab captures; telemetry is ASSISTED.
2. **0:40 Protocol Analysis / SAs:** show IKEv2, visible IKE AES256-GCM/ECP384 and ESP SPI counts. Explain that Child crypto, tunnel mode, PFS, lifetime and replay policy come separately from endpoints. Score 97.5, coverage 100%, AVAILABLE.
3. **1:30 New Analysis:** upload runtime/live/weak/negotiation.pcap and matching telemetry.json. Show 63.1, 80% coverage, PROVISIONAL, HARDEN. Actual weak configuration is CBC128/SHA256/DH14, PFS disabled and 7200-second hard lifetime. Do not claim SHA1/DH2 or disabled replay.
4. **2:20 Encrypted Traffic AI / System:** show model probabilities and abstention on real ESP. Say: “No payload was decrypted. Classification uses flow metadata.” Production remains synthetic-trained; real held-out macro F1 is only 0.32. Experimental real/mixed RF results are preliminary controlled-workload evaluation, not deployment accuracy.
5. **3:10 Threat Matrix / Findings:** show independent missing evidence, policy findings and recommendations. Open the hardening recommendation; it is not applied to the host.
6. **4:00 Reports:** download Technical HTML/PDF and Executive HTML/PDF. Show provenance, coverage and limitations.
7. **Optional:** upload demo/replay/replay.pcap, explicitly a SYNTHETIC FIXTURE. Duplicate/regression/gap signals do not prove accepted replay. Upload demo/partial/partial.pcap to show UNKNOWN configuration and unavailable score.

Transport's real capture has 28 sequence regressions and REVIEW despite high configuration score. IPv6 and forced NAT-T captures are available under their matching runtime/live directories. Capture-only analysis must leave mode/PFS/Child crypto UNKNOWN until matched telemetry is imported.

## Final pre-merge demonstration additions

Prepare with `make release-check`; namespace/live commands remain separately invoked. The
starting release head passed hosted Actions run 34203307597; current pass evidence is in
RELEASE_CHECKLIST.md. Without local live captures, use the five bundled fixtures and explicitly
call them SYNTHETIC FIXTURE throughout. Synthetic weak is 30.5/HARDEN, distinct from real weak 63.1.

- **Compare Analyses:** select strong on the left and weak on the right. Read policy, coverage,
  score delta and findings. RESOLVED is snapshot absence, not verified remediation.
- **Evidence Provenance:** show OBSERVED headers, ASSISTED endpoint configuration, INFERRED
  classifier outputs and UNKNOWN facts. DERIVED preserves computed sequence-statistic provenance.
- **Encrypted Traffic AI / System:** show EXPERIMENTAL, model hash, 22 features, production
  threshold 0.60, payload decrypted NO, attribution validated NO and controlled real macro F1 0.32.
- **Reports:** download Analysis JSON as well as HTML/PDF. Demonstrate deletion only on a
  disposable analysis: read its label/ID, type the exact ID, confirm and show the cleared selection.
