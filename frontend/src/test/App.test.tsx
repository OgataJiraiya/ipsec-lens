import { render,screen,fireEvent,waitFor } from '@testing-library/react'
import { describe,it,expect,vi } from 'vitest'
import App from '../App'
import NewAnalysis from '../components/NewAnalysis'
import { ScoreCards, EvidenceValue } from '../components/common'

import { analysis, score, response } from './fixtures'
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
 it('reports are real backend download links',async()=>{api();render(<App/>);await screen.findByText('An incomplete picture');fireEvent.click(screen.getByRole('button',{name:'Reports'}));expect(screen.getByRole('link',{name:/Download technical HTML/})).toHaveAttribute('href','/api/analyses/'+analysis.analysis_id+'/report/technical');await screen.findByText(/rekey=yes/)})
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

describe('Initial history and explicit selection',()=>{
 it('does not override an explicit empty selection with late startup history',async()=>{
  let resolveHistory:(r:Response)=>void=()=>{}
  vi.spyOn(globalThis,'fetch').mockImplementation(input=>{
   if(String(input)==='/api/analyses')return new Promise(resolve=>{resolveHistory=resolve})
   if(String(input)==='/api/health')return response({})
   return response(analysis)
  })
  render(<App/>)
  fireEvent.change(screen.getByLabelText('Selected analysis'),{target:{value:''}})
  resolveHistory({ok:true,json:()=>Promise.resolve([analysis])} as Response)
  await screen.findByRole('option',{name:'Partial capture'})
  expect(screen.getByLabelText('Selected analysis')).toHaveValue('')
  expect(screen.queryByText('An incomplete picture')).not.toBeInTheDocument()
 })
 it('clears the displayed analysis when selection is cleared',async()=>{
  api();render(<App/>)
  await screen.findByText('An incomplete picture')
  fireEvent.change(screen.getByLabelText('Selected analysis'),{target:{value:''}})
  expect(screen.queryByText('An incomplete picture')).not.toBeInTheDocument()
 })
})
