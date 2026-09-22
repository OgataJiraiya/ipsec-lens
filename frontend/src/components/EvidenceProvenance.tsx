import type { Analysis, Source } from '../api/types'
import { Badge, Panel } from './common'
import { configurationFields, ikeVersions, known } from './analysisFacts'

export default function EvidenceProvenance({run}: {run: Analysis}) {
  const groups: Record<Source, string[]> = {OBSERVED: [], ASSISTED: [], INFERRED: [], UNKNOWN: [], DERIVED: []}
  groups.OBSERVED.push(`Capture packet count: ${run.packet_count}`)
  const versions = ikeVersions(run)
  groups[versions === 'UNKNOWN' ? 'UNKNOWN' : 'OBSERVED'].push(`IKE versions: ${versions}`)
  const transforms = run.protocol_observations.ike_messages.flatMap(m => m.transforms)
  for (const t of transforms) groups[t.source].push(`Visible proposal: ${t.name} / key bits ${t.key_length ?? 'UNKNOWN'} / scope ${t.scope}`)
  if (!transforms.length) groups.UNKNOWN.push('IKE proposals: unavailable in retained visible messages')
  groups.OBSERVED.push(`NAT-T packets observed: ${run.protocol_observations.counts.NAT_T ?? 0} (zero does not prove absence elsewhere)`)
  for (const sa of run.security_associations) {
    const ref = `${sa.protocol} ${sa.spi} · ${sa.direction}`
    groups.OBSERVED.push(`${ref}: ${sa.packet_count} packets`)
    // Backend replay findings are DERIVED; do not relabel computed statistics as wire fields.
    groups.DERIVED.push(`${ref}: sequence signals ${Object.entries(sa.replay_signals).map(([k,v]) => `${k}=${v}`).join(', ')}`)
    for (const [key,label] of configurationFields) {
      const value = sa[key]
      groups[known(value) ? value.source : 'UNKNOWN'].push(`${ref} · ${label}: ${known(value) ? String(value.value) : 'UNKNOWN'}${value.evidence.length ? ' · ' + value.evidence.join('; ') : ''}`)
    }
  }
  if (!run.security_associations.length) groups.UNKNOWN.push('Child-SA cipher, mode, DH, PFS, configured lifetime, replay window and ESN: no SA evidence')
  for (const p of run.traffic_predictions) groups[p.source].push(`${p.flow_id}: ${p.predicted_class} · model confidence ${(p.confidence*100).toFixed(1)}% (metadata inference; not application attribution)`)
  if (!run.traffic_predictions.length) groups.UNKNOWN.push('Encrypted-flow classification: no eligible prediction')
  groups.UNKNOWN.push('Peer authentication / endpoint replay acceptance: not verified by passive analysis')
  return <><div className="notice">OBSERVED capture facts, ASSISTED operator assertions, and INFERRED model output answer different questions. DERIVED preserves the backend label for computed sequence statistics. UNKNOWN never means secure. IKE proposals do not establish Child-SA configuration; telemetry is not endpoint attestation.</div>
    {(['OBSERVED','ASSISTED','INFERRED','UNKNOWN','DERIVED'] as const).map(source => <Panel title={source} extra={<Badge>{source}</Badge>} key={source}>
      <ul className="limitations">{[...new Set(groups[source])].map((fact,i) => <li key={i}>{fact}</li>)}</ul>{!groups[source].length && <p>No {source.toLowerCase()} evidence available.</p>}
    </Panel>)}</>
}
