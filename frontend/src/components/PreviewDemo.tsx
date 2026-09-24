import { useState } from 'react'
import { Activity, FileText, MousePointerClick, ShieldAlert, ShieldCheck } from 'lucide-react'
import { request, type Analysis } from '../api/types'
import { Badge, Panel } from './common'

export default function PreviewDemo({onComplete}: {onComplete: (run: Analysis) => void}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function analyze(scenario: 'weak' | 'strong') {
    setBusy(true); setError('')
    try { onComplete(await request<Analysis>('/preview/demo/' + scenario, {method: 'POST'})) }
    catch { setError('Demo service is temporarily unavailable. Please retry.') }
    finally { setBusy(false) }
  }
  return <div className="preview-demo"><Panel title="QUICK INTERACTIVE DEMO" extra={<div className="fixture-caption"><Badge>SYNTHETIC FIXTURE</Badge><span>Controlled demonstration data</span></div>}>
    <div className="scenario-grid">
      <article className="scenario-card scenario-weak">
        <div className="scenario-profile"><ShieldAlert size={22} aria-hidden="true"/><span>WEAK PROFILE</span></div>
        <h3>Weak VPN Configuration</h3><p>Legacy cryptography, disabled PFS and replay-protection concerns.</p>
        <div className="scenario-features">{['AES-CBC', 'SHA-1', 'DH2', 'PFS OFF'].map(feature=><span key={feature}>{feature}</span>)}</div>
        <button className="primary" disabled={busy} onClick={()=>void analyze('weak')}>Analyze Weak VPN</button>
      </article>
      <article className="scenario-card scenario-strong">
        <div className="scenario-profile"><ShieldCheck size={22} aria-hidden="true"/><span>REFERENCE PROFILE</span></div>
        <h3>Strong VPN Configuration</h3><p>Modern cryptography and stronger security settings.</p>
        <div className="scenario-features">{['AES-GCM', 'MODERN DH', 'PFS ON', 'REPLAY PROTECTION'].map(feature=><span key={feature}>{feature}</span>)}</div>
        <button className="primary" disabled={busy} onClick={()=>void analyze('strong')}>Analyze Strong VPN</button>
      </article>
    </div>
    {busy && <p role="status" className="demo-progress">Running protocol and security analysis…</p>}
    {error && <p role="alert" className="error">{error}</p>}
    <ol className="demo-steps" aria-label="How it works">
      {([[MousePointerClick, 'Choose scenario'], [Activity, 'Run analysis'], [ShieldCheck, 'Review evidence'], [FileText, 'Export report']] as const).map(([Icon, text], index)=><li key={text}><Icon size={17} aria-hidden="true"/><div><span>0{index + 1}</span><strong>{text}</strong></div></li>)}
    </ol>
  </Panel></div>
}
