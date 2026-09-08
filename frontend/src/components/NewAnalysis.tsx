import { useRef, useState } from 'react'
import { UploadCloud, FileCheck2, Play, ShieldCheck } from 'lucide-react'
import { request, type Analysis } from '../api/types'
import { Panel } from './common'
export default function NewAnalysis({onComplete}: {onComplete: (run: Analysis) => void}) {
  const [file,setFile] = useState<File | null>(null)
  const [hash,setHash] = useState('')
  const [telemetry,setTelemetry] = useState('')
  const [policy,setPolicy] = useState('MODERN')
  const [label,setLabel] = useState('')
  const [retain,setRetain] = useState(false)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const generation = useRef(0)
  async function selectFile(next?: File) {
    const ticket = ++generation.current
    setFile(null); setHash(''); setError('')
    if (!next) return
    if (next.size > 256 * 1024 * 1024) { setError('Capture exceeds 256 MiB browser limit.'); return }
    setFile(next)
    // Browser WebCrypto digest uses a bounded buffer; backend independently hashes streamed bytes.
    try {
      const digest = await crypto.subtle.digest('SHA-256', await next.arrayBuffer())
      if (ticket === generation.current) setHash(Array.from(new Uint8Array(digest)).map(x => x.toString(16).padStart(2,'0')).join(''))
    } catch { if (ticket === generation.current) setError('Unable to hash capture. Use localhost or a secure browser context.') }
  }
  async function run() {
    if (!file || !hash) return
    setBusy(true); setError('')
    const form = new FormData()
    form.append('capture',file); form.append('policy',policy); form.append('label',label)
    form.append('retain_capture',String(retain))
    if (telemetry) form.append('telemetry',telemetry)
    try { onComplete(await request<Analysis>('/analyses',{method:'POST',body:form})) }
    catch (e) { setError(e instanceof Error ? e.message : 'Analysis failed') }
    finally { setBusy(false) }
  }
  return <div className="intake-grid"><Panel title="Capture intake" extra={<span className="muted">01 / EVIDENCE</span>}>
    <label className="drop-zone" onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault(); if(!busy) void selectFile(e.dataTransfer.files[0])}}>
      <UploadCloud size={40}/><strong>Drop a capture to begin</strong><span>PCAP or PCAPNG · up to 256 MiB</span>
      <input aria-label="Capture file" type="file" accept=".pcap,.pcapng,.cap" disabled={busy} onChange={e=>void selectFile(e.target.files?.[0])}/>
      <span className="button secondary">Browse files</span>
    </label>
    {file && <div className="file-card"><FileCheck2/><div><strong>{file.name}</strong><p>{(file.size/1024).toFixed(1)} KiB</p><code>{hash || 'Calculating SHA-256…'}</code></div></div>}
    <label>Analysis label<input value={label} maxLength={160} disabled={busy} placeholder="e.g. Gateway review · September" onChange={e=>setLabel(e.target.value)}/></label>
    <label>Endpoint telemetry JSON <span className="muted">optional · ASSISTED</span><input aria-label="Telemetry file" type="file" accept=".json" disabled={busy} onChange={async e=>{
      const value=e.target.files?.[0]; setTelemetry('')
      if(value && value.size<=2*1024*1024) { try { const text=await value.text(); JSON.parse(text); setTelemetry(text) } catch {setError('Invalid telemetry JSON')} }
      else if(value) setError('Telemetry exceeds 2 MiB')
    }}/></label>
    <label className="checkbox"><input type="checkbox" checked={retain} disabled={busy} onChange={e=>setRetain(e.target.checked)}/>Retain capture on this machine</label>
    {error && <div role="alert" className="error">{error}</div>}
    <button className="primary" disabled={!file || !hash || busy} onClick={()=>void run()}><Play size={16}/>{busy ? 'Analyzing evidence…' : 'Run analysis'}</button>
  </Panel><div><Panel title="Assessment policy" extra={<ShieldCheck size={18}/>}>
    {['MODERN','COMPATIBILITY','STRICT'].map(p=><label className={'policy-option ' +(policy===p?'selected':'')} key={p}><input type="radio" name="policy" value={p} disabled={busy} checked={policy===p} onChange={()=>setPolicy(p)}/><div><strong>{p}</strong><p>{p==='MODERN'?'AEAD, modern DH, PFS and replay protection':p==='STRICT'?'256-bit AES, stronger ECDH set, shorter lifetimes':'Allows CBC + SHA-2 and DH14 for interoperability'}</p></div></label>)}
    </Panel><div className="notice"><strong>Evidence before certainty</strong><p>IKE proposals do not establish ESP Child-SA algorithms. Import matching telemetry to assess PFS, lifetime, replay window and operating mode.</p><p>Uploads are deleted after analysis unless retention is selected. The backend never runs privileged capture commands.</p></div></div></div>
}
