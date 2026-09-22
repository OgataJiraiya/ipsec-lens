import type { Analysis, Evidence, SA } from '../api/types'

export const configurationFields = [
  ['mode', 'Mode'], ['encryption_algorithm', 'Child-SA cipher'],
  ['encryption_key_bits', 'Key strength (bits)'], ['integrity_algorithm', 'Integrity'],
  ['dh_group', 'Child-SA DH group'], ['pfs_enabled', 'PFS'],
  ['configured_lifetime', 'Configured lifetime (s)'], ['replay_window', 'Replay window'], ['esn', 'ESN'],
] as const satisfies ReadonlyArray<readonly [keyof SA, string]>
export const known = (e: Evidence) => e.value !== null && e.source !== 'UNKNOWN'
export const saIdentity = (sa: SA) => [sa.source, sa.destination, sa.protocol, sa.spi].join(' | ')
export function ikeVersions(run: Analysis) {
  const versions = ['IKEv1', 'IKEv2'].filter(v => run.protocol_observations.counts[v] > 0)
  return (versions.length ? versions : [...new Set(run.protocol_observations.ike_messages.map(m => m.version))]).join(', ') || 'UNKNOWN'
}
export function numberDelta(before: number | null, after: number | null, scale = 1) {
  if (before === null || after === null) return 'UNKNOWN'
  const delta = (after - before) * scale
  return delta === 0 ? 'UNCHANGED' : `${delta > 0 ? '+' : ''}${delta.toFixed(1)}`
}
export function configurationChanges(left: Analysis, right: Analysis) {
  const before = new Map(left.security_associations.map(sa => [saIdentity(sa), sa]))
  const after = new Map(right.security_associations.map(sa => [saIdentity(sa), sa]))
  return [...new Set([...before.keys(), ...after.keys()])].flatMap(identity => {
    const a = before.get(identity), b = after.get(identity)
    if (!a || !b) return [{identity, field: 'Directional SA', change: b ? 'ADDED observation' : 'RESOLVED observation (absent)', before: a ? 'Observed' : 'UNKNOWN', after: b ? 'Observed' : 'UNKNOWN'}]
    return configurationFields.map(([key, field]) => ({identity, field,
      before: known(a[key]) ? String(a[key].value) : 'UNKNOWN',
      after: known(b[key]) ? String(b[key].value) : 'UNKNOWN',
      change: !known(a[key]) || !known(b[key]) ? 'UNKNOWN' : a[key].value === b[key].value && a[key].source === b[key].source ? 'UNCHANGED' : 'CHANGED',
    }))
  })
}
export function findingChanges(left: Analysis, right: Analysis) {
  // Stable backend evidence identities; never infer remediation from category counts.
  const key = (f: Analysis['findings'][number]) => JSON.stringify([f.finding_id, f.severity, f.source, f.reason])
  const a = new Set(left.findings.map(key)), b = new Set(right.findings.map(key))
  return {added: right.findings.filter(f => !a.has(key(f))), resolved: left.findings.filter(f => !b.has(key(f)))}
}
