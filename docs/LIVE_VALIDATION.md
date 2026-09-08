# Live validation — 2026-09-08

Actual strongSwan 6.0.7 SAs were established in disposable Linux user/network/mount namespaces. Docker 28.5.2 / Compose 2.40.3-3 are installed but daemon access is denied. No group membership or host VPN configuration was changed. If desired, the user can run `sudo usermod -aG docker "$USER"`, then log out/in or run `newgrp docker`. No password was requested or stored.

## Reproduce locally

Requires Linux unprivileged user namespaces, strongSwan charon-systemd and swanctl with the installed crypto/VICI plugins, iproute2, tcpdump, tshark, curl and Python dependencies. Namespace creation may need execution outside a restrictive application sandbox.

```sh
unshare --user --map-root-user --mount --net .venv/bin/python -m testbed.scripts.live_namespaces --name strong
# Repeat --name weak, transport, ipv6, natt, sensor
.venv/bin/python -m scripts.crosscheck_live
unshare --user --map-root-user --mount --net .venv/bin/python -m testbed.scripts.live_namespaces --dataset
.venv/bin/python -m training.real_evaluate
```

Endpoint veth pairs have no external route. Separate mounts isolate /run and VICI. Local ping/HTTP and generated UDP workloads traverse real authenticated ESP. Captures, keys, daemon logs and unsanitized XFRM state stay under ignored runtime/live. Never publish that directory. Small committed text fixtures replace XFRM key material with REDACTED. No real PCAP was committed.

## Observed results

| Scenario | Frames | IKE | ESP | Security / coverage | Disposition |
|---|---:|---:|---:|---|---|
| Strong | 1223 | 8 | 1215 | 97.5 / 100% AVAILABLE | ACCEPT |
| Weak | 1202 | 8 | 1194 | 63.1 / 80% PROVISIONAL | HARDEN |
| Transport | 1146 | 8 | 1138 | 97.5 / 100% AVAILABLE | REVIEW |
| IPv6 | 1251 | 8 | 1243 | 97.5 / 100% AVAILABLE | ACCEPT |
| Forced NAT-T | 1238 | 8 | 1230 | 97.5 / 100% AVAILABLE | ACCEPT |

Strong IKE: AES_GCM_16_256, PRF_HMAC_SHA2_384, ECP_384. Rekeyed Child SA: AES_GCM_16_256, ECP_384; configured PFS enabled, tunnel, hard lifetime 3600 seconds, inbound replay window 64, ESN false.

Weak IKE: AES_CBC_128, HMAC_SHA2_256_128, PRF_HMAC_SHA2_256, MODP_2048. Child: AES_CBC_128 with HMAC_SHA2_256_128, configured PFS disabled, hard lifetime 7200 seconds, inbound replay window 64. SHA1/DH2 were not negotiated. Findings concern CBC policy, key length preference, DH14 review, disabled PFS and longer lifetime. Missing Child DH stays UNKNOWN.

Transport mode is established and resolved only by ASSISTED telemetry. Its capture contains 28 sequence regressions, independently confirmed by tshark; these justify REVIEW despite a high configuration score. They do not prove replay acceptance or malicious action. IPv6 validates ordinary outer IPv6; extension-chain cases remain offline tests. Forced ESP-in-UDP validates NAT-T encoding, not traversal through an actual NAT router.

Tshark agrees on frame and ESP counts, IKE versions/exchanges/SPIs, visible transform IDs and directional ESP sequence sets. See LIVE_PROTOCOL_VALIDATION.json. Passive-only mode/PFS remain UNKNOWN before telemetry import.

## Telemetry semantics

Actual list-sas/list-conns raw and XFRM state/policy text are parsed with bounded grammar. Remaining swanctl life-time is not configured lifetime. XFRM hard expire-add supplies configured lifetime. GCM key bits exclude the 32-bit salt. Extended replay_window takes precedence over legacy replay-window; outbound zero does not establish disabled inbound protection. An anti-replay esn context heading alone does not enable ESN. Optional NONE in Child proposals prevents a positive mandatory-PFS assertion. Conflicts fail import; missing fields remain UNKNOWN. Endpoint assertions are ASSISTED, not authenticated by the analyzer.

The capture sensor passed interface enumeration, normal duration, byte-ceiling cleanup and SIGINT cleanup in isolation. Exclusive no-follow creation prevents destination symlink replacement. The web service remains unprivileged.

## Real traffic evaluation

120 independently captured generated-workload sessions, 12 fresh tunnel groups, five classes (ICMP, WEB, VOIP, MESSAGING, VIDEO), both GCM and CBC. Groups 0–2 per cipher train; group 3 validates; groups 4–5 test: 60/20/40 sessions. One predetermined dominant direction per session. No split shares a tunnel/session or paired workload seed. Cross-crypto tests use only held-out target groups.

Synthetic-trained → held-out real: accuracy 0.45, macro F1 0.32, weighted F1 0.32. Real-only and mixed-training RF experiments: accuracy/macro/weighted F1 1.00 on 40 held-out sessions. Cross-crypto directions: 1.00 on 20 held-out sessions each. These are preliminary single-host testbed results, not operational accuracy benchmarks. See REAL_ML_EVALUATION.json for per-class metrics, matrices, Brier/ECE, candidate comparisons and exact group IDs.

Validation selected threshold 0.90 for experiments. Production retains the original synthetic model and threshold 0.60. No test-set tuning or silent model replacement. No payload was decrypted by the analyzer. VOIP/MESSAGING/VIDEO label generated workloads, not identified commercial applications. EMAIL/OTHER have no real validation sessions.
