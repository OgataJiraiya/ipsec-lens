import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import CompareAnalyses from '../components/CompareAnalyses'
import EvidenceProvenance from '../components/EvidenceProvenance'
import ModelTransparency from '../components/ModelTransparency'
import DeleteAnalysis from '../components/DeleteAnalysis'
import { configurationChanges, findingChanges, ikeVersions, numberDelta } from '../components/analysisFacts'
import App from '../App'
import type { Analysis, SA, Evidence } from '../api/types'
import { analysis, score, response } from './fixtures'
const unknown: Evidence = {value:null, source:'UNKNOWN', confidence:0, evidence:[]}
const sa: SA = {sa_id:'flow',spi:'0x00000001',direction:'192.0.2.1 → 192.0.2.2',source:'192.0.2.1',destination:'192.0.2.2',protocol:'ESP',ip_version:4,nat_t:false,first_seen:0,last_seen:2,observed_duration:2,packet_count:22,bytes:4400,mean_packet_size:200,std_packet_size:0,packet_rate:11,sequence_min:1,sequence_max:22,replay_signals:{duplicates:1,regressions:1,large_gaps:0,zero_sequences:0},mode:unknown,encryption_algorithm:unknown,encryption_key_bits:unknown,integrity_algorithm:unknown,pfs_enabled:unknown,dh_group:unknown,configured_lifetime:unknown,replay_window:unknown,esn:unknown}
const left: Analysis = {...analysis, label:'Baseline',security_associations:[sa],score:{...score,security_score:60,risk_score:40,assessment_coverage:.6}}
const right: Analysis = {...left,analysis_id:'c'.repeat(32),label:'Candidate',score:{...left.score,security_score:80,assessment_coverage:.8},findings:[{...analysis.findings[0],finding_id:'new',category:'NEW_FINDING'}]}
function compareApi() {vi.spyOn(globalThis,'fetch').mockImplementation(input => response(String(input).endsWith(left.analysis_id) ? left : right))}
function selectBoth() {fireEvent.change(screen.getByLabelText('Left analysis'),{target:{value:left.analysis_id}});fireEvent.change(screen.getByLabelText('Right analysis'),{target:{value:right.analysis_id}})}
describe('Comparison', () => {
  it('renders two valid analyses and score/coverage deltas',async () => {compareApi();render(<CompareAnalyses history={[left,right]}/>);selectBoth();expect(await screen.findAllByText('+20.0')).toHaveLength(2);expect(screen.getByText(/NEW_FINDING:/)).toBeVisible();expect(screen.getByText(/ESP_DUPLICATE_SEQUENCE:/)).toBeVisible()})
  it('never equates two unknown configurations or subtracts an unavailable score', () => {expect(numberDelta(null,80)).toBe('UNKNOWN');expect(numberDelta(80,null)).toBe('UNKNOWN');expect(numberDelta(0,0)).toBe('UNCHANGED');expect(configurationChanges(left,right).every(r=>r.change==='UNKNOWN')).toBe(true)})
  it('distinguishes false and zero from UNKNOWN and matches only exact directional SAs', () => {const known = {...sa,pfs_enabled:{value:false,source:'ASSISTED' as const,confidence:.9,evidence:[]},replay_window:{value:0,source:'ASSISTED' as const,confidence:.9,evidence:[]}};const a={...left,security_associations:[known]};expect(configurationChanges(a,a).filter(r=>r.change==='UNCHANGED')).toHaveLength(2);expect(configurationChanges(a,{...right,security_associations:[{...known,spi:'0x00000002'}]}).map(r=>r.change)).toEqual(['RESOLVED observation (absent)','ADDED observation'])})
  it('requires both selections and clears deltas on deselection',async () => {compareApi();render(<CompareAnalyses history={[left,right]}/>);selectBoth();await screen.findAllByText('+20.0');fireEvent.change(screen.getByLabelText('Right analysis'),{target:{value:''}});expect(screen.queryByText('+20.0')).not.toBeInTheDocument();expect(screen.getByText(/Two existing analyses/)).toBeVisible()})
  it('shows missing analysis errors without stale deltas',async () => {vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({detail:'Analysis not found'},false));render(<CompareAnalyses history={[left,right]}/>);selectBoth();expect(await screen.findAllByRole('alert')).toHaveLength(2);expect(screen.queryByText('+20.0')).not.toBeInTheDocument()})
  it('ignores a stale response even when transport ignores abort',async () => {let resolve:(r:Response)=>void=()=>{};vi.spyOn(globalThis,'fetch').mockImplementation(input=>String(input).endsWith(left.analysis_id)?new Promise(r=>{resolve=r}):response(right));render(<CompareAnalyses history={[left,right]}/>);fireEvent.change(screen.getByLabelText('Left analysis'),{target:{value:left.analysis_id}});fireEvent.change(screen.getByLabelText('Left analysis'),{target:{value:right.analysis_id}});await screen.findByText('Candidate / partial.pcap');await act(async()=>resolve(await response(left)));expect(screen.queryByText('Baseline / partial.pcap')).not.toBeInTheDocument()})
  it('invalidates a selection removed from refreshed history',async () => {compareApi();const view=render(<CompareAnalyses history={[left,right]}/>);selectBoth();await screen.findAllByText('+20.0');view.rerender(<CompareAnalyses history={[left]}/>);expect(screen.queryByText('+20.0')).not.toBeInTheDocument();expect(screen.getByLabelText('Right analysis')).toHaveValue('')})
  it('computes finding deltas from backend identities including changed severity',()=>{expect(findingChanges(left,right).added).toHaveLength(1);expect(findingChanges(left,right).resolved).toHaveLength(2);expect(findingChanges(left,left)).toEqual({added:[],resolved:[]});expect(findingChanges(left,{...left,findings:left.findings.map(f=>({...f,severity:'HIGH'}))}).added).toHaveLength(2)})
  it('uses all-message IKE counters beyond retained detail',()=>{expect(ikeVersions({...left,protocol_observations:{...left.protocol_observations,counts:{IKEv1:1,IKEv2:4096}}})).toBe('IKEv1, IKEv2')})
})
describe('Evidence and model transparency',()=>{
  it('preserves actual provenance and computed sequence labels',()=>{const assisted={value:false,source:'ASSISTED' as const,confidence:.9,evidence:['Endpoint assertion']};render(<EvidenceProvenance run={{...left,security_associations:[{...sa,pfs_enabled:assisted}]}}/>);const group=(name:string)=>within(screen.getByRole('heading',{name}).closest('section')!);expect(group('ASSISTED').getByText(/PFS: false/)).toBeVisible();expect(group('UNKNOWN').getByText(/Child-SA cipher: UNKNOWN/)).toBeVisible();expect(group('DERIVED').getByText(/sequence signals/)).toBeVisible();expect(group('OBSERVED').queryByText(/PFS/)).not.toBeInTheDocument()})
  it('retains inference source even for abstention',()=>{render(<EvidenceProvenance run={{...left,traffic_predictions:[{flow_id:'flow',predicted_class:'UNKNOWN',confidence:0,probabilities:{},features:{},limitations:[],source:'INFERRED'}]}}/>);expect(within(screen.getByRole('heading',{name:'INFERRED'}).closest('section')!).getByText(/flow: UNKNOWN/)).toBeVisible()})
  it('exposes production metadata and real transfer failure separately from synthetic metrics',async()=>{vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({status:'AVAILABLE',kind:'RandomForest',model_sha256:'e'.repeat(64),features:Array(22).fill('feature'),abstention_threshold:.6,metadata:{training_source:'SYNTHETIC FIXTURE'},metrics:{test:{macro_f1:1,accuracy:1}},real_testbed_evaluation:{synthetic_to_real:{test:{macro_f1:.32}}}}));render(<ModelTransparency/>);expect(await screen.findByText('RandomForest')).toBeVisible();for(const text of ['EXPERIMENTAL','0.32','22','0.6','metadata inference','SYNTHETIC held-out macro F1','Real-world application attribution validated'])expect(screen.getByText(text)).toBeVisible();expect(screen.getAllByText('NO')).toHaveLength(2);expect(screen.getByText(/Confident errors/)).toBeVisible()})
  it('keeps caveats and UNKNOWN visible when metadata fails',async()=>{vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({detail:'Unavailable'},false));render(<ModelTransparency/>);await screen.findByRole('alert');expect(screen.getByText('EXPERIMENTAL')).toBeVisible();expect(screen.getAllByText('UNKNOWN').length).toBeGreaterThan(0);expect(screen.queryByText('0.32')).not.toBeInTheDocument()})
})
describe('Export and deletion',()=>{
  it('requires exact confirmation and supports cancellation',()=>{const fetcher=vi.spyOn(globalThis,'fetch');render(<DeleteAnalysis run={left} onDeleted={vi.fn()}/>);fireEvent.click(screen.getByRole('button',{name:'Delete analysis'}));expect(screen.getByText('Baseline')).toBeVisible();expect(screen.getByText(left.analysis_id)).toBeVisible();expect(screen.getByRole('button',{name:'Confirm delete analysis'})).toBeDisabled();fireEvent.change(screen.getByLabelText('Type analysis ID to confirm'),{target:{value:'wrong'}});expect(screen.getByRole('button',{name:'Confirm delete analysis'})).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:'Cancel'}));expect(fetcher).not.toHaveBeenCalled()})
  it('keeps analysis on deletion failure and permits retry',async()=>{vi.spyOn(globalThis,'fetch').mockImplementation(()=>response({detail:'Capture cleanup failed'},false));const done=vi.fn();render(<DeleteAnalysis run={left} onDeleted={done}/>);fireEvent.click(screen.getByRole('button',{name:'Delete analysis'}));fireEvent.change(screen.getByLabelText('Type analysis ID to confirm'),{target:{value:left.analysis_id}});fireEvent.click(screen.getByRole('button',{name:'Confirm delete analysis'}));expect(await screen.findByRole('alert')).toHaveTextContent('Capture cleanup failed');expect(done).not.toHaveBeenCalled();expect(screen.getByRole('button',{name:'Confirm delete analysis'})).toBeEnabled()})
  it.skipIf(import.meta.env.VITE_SUBMISSION_PREVIEW === 'true')('downloads JSON through fixed API route and clears deleted selection despite stale history',async()=>{vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{const path=String(input);if(path==='/api/health')return response({});if(path==='/api/analyses')return response([left]);if(init?.method==='DELETE')return response({status:'DELETED'});if(path.endsWith('/hardening'))return response({snippet:'RECOMMENDATION'});return response(left)});render(<App/>);await screen.findByText('An incomplete picture');fireEvent.click(screen.getByRole('button',{name:'Reports'}));expect(screen.getByRole('link',{name:'Download Analysis JSON'})).toHaveAttribute('href','/api/analyses/'+left.analysis_id+'/export');fireEvent.click(screen.getByRole('button',{name:'Delete analysis'}));fireEvent.change(screen.getByLabelText('Type analysis ID to confirm'),{target:{value:left.analysis_id}});fireEvent.click(screen.getByRole('button',{name:'Confirm delete analysis'}));await waitFor(()=>expect(screen.getByLabelText('Selected analysis')).toHaveValue(''));expect(screen.queryByRole('link',{name:'Download Analysis JSON'})).not.toBeInTheDocument();expect(screen.queryByRole('option',{name:'Baseline'})).not.toBeInTheDocument()})
})

describe('Lifecycle selection races',()=>{
  it.skipIf(import.meta.env.VITE_SUBMISSION_PREVIEW === 'true')('does not clear a newer selection when an older deletion finishes',async()=>{
    let finishDelete:(r:Response)=>void=()=>{}
    vi.spyOn(globalThis,'fetch').mockImplementation((input,init)=>{
      const path=String(input)
      if(path==='/api/health')return response({})
      if(path==='/api/analyses')return response([left,right])
      if(init?.method==='DELETE')return new Promise(r=>{finishDelete=r})
      if(path.endsWith('/hardening'))return response({snippet:'RECOMMENDATION'})
      return response(path.endsWith(left.analysis_id)?left:right)
    })
    render(<App/>);await screen.findByText('An incomplete picture')
    fireEvent.click(screen.getByRole('button',{name:'Reports'}))
    fireEvent.click(screen.getByRole('button',{name:'Delete analysis'}))
    fireEvent.change(screen.getByLabelText('Type analysis ID to confirm'),{target:{value:left.analysis_id}})
    fireEvent.click(screen.getByRole('button',{name:'Confirm delete analysis'}))
    fireEvent.change(screen.getByLabelText('Selected analysis'),{target:{value:right.analysis_id}})
    await waitFor(()=>expect(screen.getByRole('link',{name:'Download Analysis JSON'})).toHaveAttribute('href','/api/analyses/'+right.analysis_id+'/export'))
    await act(async()=>finishDelete(await response({status:'DELETED'})))
    expect(screen.getByLabelText('Selected analysis')).toHaveValue(right.analysis_id)
    expect(screen.getByRole('link',{name:'Download Analysis JSON'})).toHaveAttribute('href','/api/analyses/'+right.analysis_id+'/export')
  })
  it.skipIf(import.meta.env.VITE_SUBMISSION_PREVIEW === 'true')('does not apply a global synthetic banner to unrelated comparisons',async()=>{
    vi.spyOn(globalThis,'fetch').mockImplementation(input=>String(input)==='/api/analyses'?response([{...left,capture_source:'SYNTHETIC_FIXTURE'},right]):response({...left,capture_source:'SYNTHETIC_FIXTURE'}))
    render(<App/>);await screen.findByText('An incomplete picture')
    expect(screen.getByText(/Bundled capture or endpoint assertions/)).toBeVisible()
    fireEvent.click(screen.getByRole('button',{name:'Compare Analyses'}))
    expect(screen.queryByText(/Bundled capture or endpoint assertions/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Selected analysis')).not.toBeInTheDocument()
  })
})
