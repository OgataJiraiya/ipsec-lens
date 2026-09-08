import { render,screen,fireEvent,waitFor } from '@testing-library/react'
import { describe,it,expect,vi } from 'vitest'
import App from '../App'
import NewAnalysis from '../components/NewAnalysis'
import { ScoreCards, EvidenceValue } from '../components/common'
import type { Analysis } from '../api/types'

const score={security_score:null,risk_score:null,assessment_coverage:.05,score_status:'UNAVAILABLE',overall_disposition:'REVIEW',domains:[{name:'Cryptography',score:null,weight:.25,coverage:0,evidence:['No telemetry']}]}
const analysis: Analysis={analysis_id:'a'.repeat(32),created_at:'2026-01-01',label:'Partial capture',capture_filename:'partial.pcap',packet_count:22,policy:'MODERN',score,capture_sha256:'b'.repeat(64),capture_size:1000,capture_duration:2,analysis_status:'COMPLETE',protocol_observations:{counts:{ESP:22},ike_messages:[],spi_changes:0,malformed_packets:0,unsupported_packets:0,ah_next_headers:[]},security_associations:[],traffic_predictions:[],findings:[{finding_id:'1',category:'ESP_DUPLICATE_SEQUENCE',severity:'MEDIUM',confidence:.95,source:'DERIVED',reason:'Duplicate sequence observed',evidence:['seq=2'],recommendation:'REVIEW',remediation:'Review capture artifacts',limitations:[]},{finding_id:'2',category:'INSUFFICIENT_EVIDENCE',severity:'LOW',confidence:0,source:'UNKNOWN',reason:'Missing telemetry',evidence:[],recommendation:'REVIEW',remediation:'Import telemetry',limitations:[]}],threat_matrix:[],limitations:['UNKNOWN != SECURE'],report_references:{},telemetry_provenance:[],revision:1}
const response=(body: unknown,ok=true)=>Promise.resolve({ok,status:ok?200:422,json:()=>Promise.resolve(body)} as Response)
function api() {
 return vi.spyOn(globalThis,'fetch').mockImplementation((input)=>{
  const path=String(input)
  if(path==='/api/health')return response({status:'ok'})
  if(path==='/api/analyses')return response([analysis])
  if(path.endsWith('/hardening'))return response({snippet:'RECOMMENDATION\nrekey=yes'})
  return response(analysis)
 })
}
describe('Evidence presentation',()=>{
 it('keeps unknown scores explicit',()=>{render(<ScoreCards score={score}/>);expect(screen.getAllByText('UNKNOWN')).toHaveLength(2);expect(screen.getByText('UNAVAILABLE')).toBeVisible();expect(screen.getByText('5%')).toBeVisible()})
 it('does not render absent PFS as enabled',()=>{render(<EvidenceValue value={{value:null,source:'UNKNOWN',confidence:0,evidence:[]}}/>);expect(screen.getAllByText('UNKNOWN')).toHaveLength(2);expect(screen.queryByText('true')).not.toBeInTheDocument()})
 it('filters findings by severity and category',async()=>{api();render(<App/>);await screen.findByText('An incomplete picture');fireEvent.click(screen.getByRole('button',{name:/^Findings/}));fireEvent.change(screen.getByLabelText('Severity filter'),{target:{value:'MEDIUM'}});expect(screen.getByText('Duplicate sequence observed')).toBeVisible();expect(screen.queryByText('Missing telemetry')).not.toBeInTheDocument();fireEvent.change(screen.getByLabelText('Category filter'),{target:{value:'missing-category'}});expect(screen.getByText(/No findings match/)).toBeVisible()})
 it('reports are real backend download links',async()=>{api();render(<App/>);await screen.findByText('An incomplete picture');fireEvent.click(screen.getByRole('button',{name:'Reports'}));expect(screen.getByRole('link',{name:/Download technical/})).toHaveAttribute('href','/api/analyses/'+analysis.analysis_id+'/report/technical');await screen.findByText(/rekey=yes/)})
 it('handles history failures',async()=>{vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({detail:'Service unavailable'},false));render(<App/>);expect(await screen.findByRole('alert')).toHaveTextContent('Service unavailable')})
 it('discards stale analysis responses',async()=>{
   const second={...analysis,analysis_id:'c'.repeat(32),label:'Second analysis'}
   let resolveFirst:(v:Response)=>void=()=>{}
   vi.spyOn(globalThis,'fetch').mockImplementation(input=>{
    const path=String(input)
    if(path==='/api/health')return response({})
    if(path==='/api/analyses')return response([analysis,second])
    if(path.endsWith(analysis.analysis_id))return new Promise(resolve=>{resolveFirst=resolve})
    return response(second)
   })
   render(<App/>)
   await screen.findByRole('option',{name:'Second analysis'})
   fireEvent.change(screen.getByLabelText('Selected analysis'),{target:{value:second.analysis_id}})
   await screen.findByText('An incomplete picture')
   resolveFirst({ok:true,json:()=>Promise.resolve({...analysis,score:{...score,overall_disposition:'QUARANTINE'}})} as Response)
   await waitFor(()=>expect(screen.queryByText('QUARANTINE')).not.toBeInTheDocument())
   expect(screen.getByLabelText('Selected analysis')).toHaveValue(second.analysis_id)
 })
})
describe('Capture intake',()=>{
 function prepare() {
   vi.spyOn(crypto.subtle,'digest').mockResolvedValue(new Uint8Array(32).buffer)
   const file=new File(['pcap'],'sample.pcap',{type:'application/octet-stream'})
   Object.defineProperty(file,'arrayBuffer',{value:async()=>new ArrayBuffer(4)})
   return file
 }
 it('runs an actual multipart upload with selected policy',async()=>{
  const file=prepare(),complete=vi.fn()
  const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(()=>response(analysis))
  render(<NewAnalysis onComplete={complete}/>)
  fireEvent.change(screen.getByLabelText('Capture file'),{target:{files:[file]}})
  fireEvent.click(screen.getByRole('radio',{name:/COMPATIBILITY/}))
  await waitFor(()=>expect(screen.getByRole('button',{name:'Run analysis'})).toBeEnabled())
  fireEvent.click(screen.getByRole('button',{name:'Run analysis'}))
  await waitFor(()=>expect(complete).toHaveBeenCalledWith(analysis))
  const body=fetcher.mock.calls[0][1]?.body as FormData
  expect(body.get('policy')).toBe('COMPATIBILITY')
  expect(body.get('retain_capture')).toBe('false')
 })
 it('shows backend parser errors and allows retry',async()=>{
  const file=prepare()
  vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({detail:'Truncated capture record'},false))
  render(<NewAnalysis onComplete={vi.fn()}/>)
  fireEvent.change(screen.getByLabelText('Capture file'),{target:{files:[file]}})
  await waitFor(()=>expect(screen.getByRole('button',{name:'Run analysis'})).toBeEnabled())
  fireEvent.click(screen.getByRole('button',{name:'Run analysis'}))
  expect(await screen.findByRole('alert')).toHaveTextContent('Truncated capture record')
 })
})
