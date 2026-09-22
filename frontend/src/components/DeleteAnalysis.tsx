import { useState } from 'react'
import { request, type Analysis } from '../api/types'
import { Panel } from './common'

export default function DeleteAnalysis({run,onDeleted}: {run: Analysis; onDeleted: (id: string) => void}) {
  const [confirm,setConfirm] = useState(false), [typed,setTyped] = useState(''), [busy,setBusy] = useState(false), [error,setError] = useState('')
  async function remove() {
    setBusy(true); setError('')
    try {await request('/analyses/'+run.analysis_id,{method:'DELETE'}); onDeleted(run.analysis_id)}
    catch(e) {setError(String(e)); setBusy(false)}
  }
  return <Panel title="Local analysis lifecycle"><p>Delete this persisted analysis and its retained capture, if any. Exported reports and files you downloaded are separate copies.</p>
    {!confirm ? <button className="secondary danger" onClick={() => setConfirm(true)}>Delete analysis</button> : <div role="group" aria-label="Confirm analysis deletion">
      <p>Delete <strong>{run.label || run.capture_filename}</strong> (<code>{run.analysis_id}</code>)? This cannot be undone.</p>
      <label>Type analysis ID to confirm<input aria-label="Type analysis ID to confirm" value={typed} disabled={busy} onChange={e => setTyped(e.target.value)}/></label>
      <div className="filters"><button className="secondary danger" disabled={typed !== run.analysis_id || busy} onClick={() => void remove()}>{busy ? 'Deleting…' : 'Confirm delete analysis'}</button><button className="secondary" disabled={busy} onClick={() => {setConfirm(false);setTyped('')}}>Cancel</button></div>
    </div>}{error && <p role="alert">{error}</p>}
  </Panel>
}
