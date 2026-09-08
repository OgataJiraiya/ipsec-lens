import type { ReactNode } from 'react'
import type { Evidence, Score } from '../api/types'
export const percent = (v: number) => (v * 100).toFixed(0) + '%'
export function Badge({children}: {children: ReactNode}) { return <span className={'badge ' + String(children).toLowerCase()}>{children}</span> }
export function EvidenceValue({value}: {value: Evidence}) { return <div className="evidence-value" title={value.evidence.join('\n')}><span>{value.value === null ? 'UNKNOWN' : String(value.value)}</span><Badge>{value.source}</Badge></div> }
export function Panel({title, extra, children}: {title: string; extra?: ReactNode; children: ReactNode}) { return <section className="panel"><div className="panel-heading"><h2>{title}</h2>{extra}</div>{children}</section> }
export function ScoreCards({score}: {score: Score}) { return <div className="metrics">
  {[['Security score', score.security_score ?? 'UNKNOWN', score.score_status], ['Risk score', score.risk_score ?? 'UNKNOWN', 'Inverse of available score'], ['Assessment coverage', percent(score.assessment_coverage), 'Known weighted checks'], ['Disposition', score.overall_disposition, 'Policy decision · not certification']].map(([label,value,detail]) =>
    <div className="metric" key={label}><span>{label}</span><strong className={value === 'HARDEN' ? 'amber' : ''}>{value}</strong><small>{detail}</small></div>)}
</div> }
export function Empty({children}: {children?: ReactNode}) { return <div className="empty">{children ?? 'No observations available in this capture.'}</div> }
