# Testbed status

See [testbed instructions](../testbed/README.md) and docker-compose.yml.
Live namespace integration is verified; see LIVE_VALIDATION.md for measured results. Docker remains unavailable.
Docker daemon access was denied both in and outside the execution sandbox on the build host.

Supported generator combinations:
tunnel/transport, IPv4/IPv6, AES128/256-CBC + HMAC-SHA256, AES128/256-GCM,
DH14/DH19/DH31 plus ECP384 modern profile, PFS rekey DH present/absent.
An intentionally weak DH2/SHA1 profile is offered only in the isolated internal lab and may be rejected
by modern strongSwan builds. No host VPN configuration or external interface was modified.

StrongSwan fresh-DH semantics and configured lifetime must be verified on a real established SA.
The generated rekey_time differs from life_time (hard expiration). Telemetry configured_lifetime should
record the actual relevant endpoint lifetime, with provenance, rather than observed capture duration.

The five committed demonstrations use real parsing of synthetic wire-format records and synthetic
telemetry, never precomputed analyzer results. Both UI and reports disclose generated telemetry provenance.
- strong: IKEv2, AES256-GCM proposal, ECP384; synthetic matched configuration.
- weak: CBC/SHA1/DH2, synthetic no-PFS/long-lifetime/replay-disabled, passive sequence anomalies.
- replay: duplicates/regressions/gaps without endpoint configuration.
- partial: ESP without visible IKE or telemetry.
- ipv6: IKEv2/NAT-T ESP plus one AH header; AH configuration unknown.

Do not describe fallback fixtures as captured deployments or cryptographically valid functioning tunnels.

## Live validation update

See [../docs/LIVE_VALIDATION.md](../docs/LIVE_VALIDATION.md) for real strong/weak, transport, IPv6 and forced NAT-T verification. Real generated-workload dataset: 120 sessions; group-safe preliminary evaluation is recorded separately from synthetic metrics. Production retains the original synthetic classifier; its held-out real macro F1 is 0.32. HTML and bounded offline server PDF reports are verified.
