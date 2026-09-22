import { useEffect, useState } from 'react'
import { request } from '../api/types'
import { Badge, Panel } from './common'

interface ModelInfo {
  status: string; kind?: string; model_sha256?: string; features: string[]; abstention_threshold: number;
  metadata?: {training_source?: string}; metrics?: {test?: {macro_f1: number; accuracy: number}};
  real_testbed_evaluation?: {synthetic_to_real?: {test?: {macro_f1: number}}};
}
export default function ModelTransparency() {
  const [data,setData] = useState<ModelInfo | null>(null), [error,setError] = useState('')
  useEffect(() => {
    const a = new AbortController()
    request<ModelInfo>('/model/info',{signal:a.signal}).then(value => {if (!a.signal.aborted) setData(value)})
      .catch(e => {if (!a.signal.aborted) setError(String(e))})
    return () => a.abort()
  }, [])
  const rows = [
    ['Model type',data?.kind ?? 'UNKNOWN'], ['Model SHA-256',data?.model_sha256 ?? 'UNKNOWN'],
    ['Training source',data?.metadata?.training_source ?? 'UNKNOWN'], ['Feature count',data?.features?.length ?? 'UNKNOWN'],
    ['Production threshold (current runtime)',data?.abstention_threshold ?? 'UNKNOWN'],
    ['Payload decrypted','NO'], ['Classifier role','metadata inference'], ['Real-world application attribution validated','NO'],
    ['Controlled held-out real macro F1',data?.real_testbed_evaluation?.synthetic_to_real?.test?.macro_f1 ?? 'UNKNOWN'],
    ['SYNTHETIC held-out macro F1',data?.metrics?.test?.macro_f1 ?? 'UNKNOWN'],
    ['SYNTHETIC held-out accuracy',data?.metrics?.test?.accuracy ?? 'UNKNOWN'],
  ]
  return <Panel title="Experimental encrypted-flow metadata classification" extra={<Badge>EXPERIMENTAL</Badge>}>
    <p>Production is synthetic-trained. AI confidence is not attack probability or real-world accuracy. No payload was decrypted. Confident errors under domain shift remain possible.</p>
    <p className="muted">Controlled real evaluation uses a small single-host generated-workload dataset; it does not validate organic application attribution. Experimental real-only models are not deployed. SYNTHETIC metrics measure generated profile recognition only.</p>
    {error && <p role="alert">{error}</p>}{!data && !error && <p>Loading trusted local model metadata…</p>}
    <dl className="fact-list">{rows.map(([label,value]) => <div key={label}><dt>{label}</dt><dd>{String(value)}</dd></div>)}</dl>
    {data && <details><summary>Full trusted model metadata</summary><pre>{JSON.stringify(data,null,2)}</pre></details>}
    <p className="muted">Fixed local JSON artifact and checked SHA-256. User model uploads are not accepted. Runtime metadata comes only from bundled model and evaluation files.</p>
  </Panel>
}
