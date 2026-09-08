export type Source = 'OBSERVED' | 'DERIVED' | 'ASSISTED' | 'INFERRED' | 'UNKNOWN'
export interface Evidence { value: string | number | boolean | null; source: Source; confidence: number; evidence: string[] }
export interface Finding { finding_id: string; category: string; severity: string; confidence: number; source: Source; reason: string; evidence: string[]; recommendation: string; remediation: string; limitations: string[] }
export interface Domain { name: string; score: number | null; weight: number; coverage: number; evidence: string[] }
export interface Score { security_score: number | null; risk_score: number | null; assessment_coverage: number; score_status: string; overall_disposition: string; domains: Domain[] }
export interface Transform { proposal: number; protocol_id: number; transform_type: number; transform_id: number; name: string; key_length: number | null; scope: string; source: Source }
export interface Ike { src: string; dst: string; version: string; exchange: string; initiator_spi: string; responder_spi: string; flags: number; message_id: number; transforms: Transform[]; ke_group: number | null; encrypted: boolean; source: Source }
export interface SA { sa_id: string; spi: string; direction: string; source: string; destination: string; protocol: string; ip_version: number; nat_t: boolean; first_seen: number; last_seen: number; observed_duration: number; packet_count: number; bytes: number; mean_packet_size: number; std_packet_size: number; packet_rate: number; sequence_min: number; sequence_max: number; replay_signals: {duplicates: number; regressions: number; large_gaps: number; zero_sequences: number}; mode: Evidence; encryption_algorithm: Evidence; encryption_key_bits: Evidence; integrity_algorithm: Evidence; pfs_enabled: Evidence; dh_group: Evidence; configured_lifetime: Evidence; replay_window: Evidence; esn: Evidence }
export interface Prediction { flow_id: string; predicted_class: string; confidence: number; probabilities: Record<string,number>; features: Record<string,number>; limitations: string[]; source: Source }
export interface Threat { threat: string; evidence: string[]; status: string; severity: string; confidence: number; impact: string; recommendation: string }
export interface Summary { analysis_id: string; created_at: string; label: string; capture_filename: string; packet_count: number; policy: string; score: Score }
export interface Analysis extends Summary { capture_sha256: string; capture_size: number; capture_duration: number; analysis_status: string; protocol_observations: { counts: Record<string,number>; ike_messages: Ike[]; spi_changes: number; malformed_packets: number; unsupported_packets: number; ah_next_headers: number[] }; security_associations: SA[]; traffic_predictions: Prediction[]; findings: Finding[]; threat_matrix: Threat[]; limitations: string[]; report_references: Record<string,string>; telemetry_provenance: string[]; revision: number }
export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch('/api' + path, init)
  if (!response.ok) {
    let message = 'Request failed (' + response.status + ')'
    try { const body = await response.json(); if (typeof body.detail === 'string') message = body.detail } catch { /* Non-JSON transport failure retains status. */ }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}
