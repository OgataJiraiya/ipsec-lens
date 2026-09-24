import { useState } from 'react'
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
  return <Panel title="QUICK INTERACTIVE DEMO" extra={<Badge>SYNTHETIC FIXTURE</Badge>}>
    <div className="demo-grid">
      <div><h3>Weak VPN Configuration</h3><p>Analyze a controlled synthetic IPsec deployment with weak cryptographic and replay-protection settings.</p><button className="primary" disabled={busy} onClick={()=>void analyze('weak')}>Analyze Weak VPN</button></div>
      <div><h3>Strong VPN Configuration</h3><p>Analyze a controlled synthetic IPsec deployment using the stronger reference policy.</p><button className="primary" disabled={busy} onClick={()=>void analyze('strong')}>Analyze Strong VPN</button></div>
    </div>
    {busy && <p role="status">Running protocol and security analysis…</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </Panel>
}
