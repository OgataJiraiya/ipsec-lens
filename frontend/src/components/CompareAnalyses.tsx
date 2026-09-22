import { useEffect, useState } from 'react'
import { request, type Analysis, type Summary } from '../api/types'
import { Badge, Empty, EvidenceValue, Panel, percent } from './common'
import { configurationChanges, configurationFields, findingChanges, ikeVersions, numberDelta } from './analysisFacts'

function useAnalysis(id: string) {
  const [state, setState] = useState<{id: string; run?: Analysis; error?: string}>({id: ''})
  useEffect(() => {
    if (!id) return
    setState({id})
    const abort = new AbortController()
    request<Analysis>('/analyses/' + id, {signal: abort.signal})
      .then(run => { if (!abort.signal.aborted) setState({id, run}) })
      .catch(e => { if (!abort.signal.aborted) setState({id, error: String(e)}) })
    return () => abort.abort()
  }, [id])
  return id && state.id === id ? state : {id}
}
function Facts({run}: {run: Analysis}) {
  const score = run.score
  const facts = [
    ['Label / capture', `${run.label || 'Unlabelled'} / ${run.capture_filename}`],
    ['Analysis ID / revision', `${run.analysis_id} / ${run.revision}`],
    ['Policy', run.policy], ['Analysis status', run.analysis_status],
    ['Security score', score.security_score ?? 'UNKNOWN'], ['Risk score', score.risk_score ?? 'UNKNOWN'],
    ['Assessment coverage', percent(score.assessment_coverage)], ['Score status', score.score_status],
    ['Overall disposition', score.overall_disposition], ['Packet count', run.packet_count],
    ['IKE versions', ikeVersions(run)],
    ['ESP / AH SA count', ['ESP', 'AH'].map(p => run.security_associations.filter(sa => sa.protocol === p).length).join(' / ')],
  ]
  return <><dl className="fact-list">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value === 'UNKNOWN' ? <Badge>UNKNOWN</Badge> : value}</dd></div>)}</dl>
    {run.capture_source === 'SYNTHETIC_FIXTURE' && <Badge>SYNTHETIC FIXTURE</Badge>}
    <h3>Finding counts by severity</h3><div className="filters">{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => <span key={s}><Badge>{s}</Badge> {run.findings.filter(f => f.severity === s).length}</span>)}</div>
    {run.security_associations.map(sa => <details key={sa.sa_id} open><summary>{sa.protocol} {sa.spi} · {sa.direction}</summary>
      <dl className="fact-list">{configurationFields.map(([key, label]) => <div key={key}><dt>{label}</dt><dd><EvidenceValue value={sa[key]}/></dd></div>)}</dl>
      <p>Sequence signals: {Object.entries(sa.replay_signals).map(([k,v]) => `${k.replaceAll('_',' ')} ${v}`).join(' · ')}</p>
    </details>)}{!run.security_associations.length && <p>Configuration / sequence signals: UNKNOWN (no directional SAs).</p>}</>
}
export default function CompareAnalyses({history}: {history: Summary[]}) {
  const [leftId, setLeft] = useState(''), [rightId, setRight] = useState('')
  const left = useAnalysis(history.some(h => h.analysis_id === leftId) ? leftId : '')
  const right = useAnalysis(history.some(h => h.analysis_id === rightId) ? rightId : '')
  const a = left.run, b = right.run
  const changes = a && b ? findingChanges(a, b) : null
  return <><div className="notice">Compare evidence snapshots: deltas are right minus left. Different policies, coverage, capture locations or times can change results. UNKNOWN values are never treated as equal configuration. Matching SAs use exact endpoints, protocol and SPI; no rekey association is inferred.</div>
    <div className="compare-grid">{([{side:'Left', id:leftId, select:setLeft, state:left}, {side:'Right', id:rightId, select:setRight, state:right}]).map(({side,id,select,state}) => <Panel title={side + ' analysis'} key={side}>
      <label>{side} analysis<select aria-label={side + ' analysis'} value={history.some(h => h.analysis_id === id) ? id : ''} onChange={e => select(e.target.value)}><option value="">Select analysis</option>{history.map(h => <option key={h.analysis_id} value={h.analysis_id}>{h.label || h.capture_filename} · {h.analysis_id.slice(0,8)}</option>)}</select></label>
      {state.error ? <p role="alert">{state.error}</p> : state.run ? <Facts run={state.run}/> : <Empty>{state.id ? 'Loading analysis…' : 'Select an analysis to compare.'}</Empty>}
    </Panel>)}</div>
    <Panel title="Delta / change">{!a || !b || !changes ? <Empty>Two existing analyses are required. No differences inferred.</Empty> : <>
      <dl className="fact-list"><div><dt>Security score delta</dt><dd>{numberDelta(a.score.security_score,b.score.security_score)}</dd></div><div><dt>Coverage delta (percentage points)</dt><dd>{numberDelta(a.score.assessment_coverage,b.score.assessment_coverage,100)}</dd></div><div><dt>Disposition change</dt><dd>{a.score.overall_disposition === b.score.overall_disposition ? 'UNCHANGED' : `${a.score.overall_disposition} → ${b.score.overall_disposition}`}</dd></div></dl>
      <p className="muted">ADDED / RESOLVED findings refer to exact finding evidence in these snapshots. RESOLVED means absent from the right analysis; it does not prove remediation or safety. Changed evidence can appear as both ADDED and RESOLVED.</p>
      <h3>Findings introduced · ADDED</h3>{changes.added.map(f => <p key={f.finding_id}><Badge>{f.severity}</Badge> {f.category}: {f.reason}</p>)}{!changes.added.length && <p>UNCHANGED · no added findings</p>}
      <h3>Findings resolved · RESOLVED</h3>{changes.resolved.map(f => <p key={f.finding_id}><Badge>{f.severity}</Badge> {f.category}: {f.reason}</p>)}{!changes.resolved.length && <p>UNCHANGED · no absent findings</p>}
      <h3>Configuration changes</h3><div className="table-wrap"><table><thead><tr><th>Directional SA</th><th>Property</th><th>Left</th><th>Right</th><th>Change</th></tr></thead><tbody>{configurationChanges(a,b).map(row => <tr key={row.identity + row.field}><td><code>{row.identity}</code></td><td>{row.field}</td><td>{row.before}</td><td>{row.after}</td><td><Badge>{row.change}</Badge></td></tr>)}</tbody></table></div>{!a.security_associations.length && !b.security_associations.length && <p>UNKNOWN · no configuration evidence</p>}
    </>}</Panel></>
}
