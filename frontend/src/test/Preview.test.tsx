import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import App from '../App'
import NewAnalysis from '../components/NewAnalysis'
import { analysis, response } from './fixtures'

const preview = import.meta.env.VITE_SUBMISSION_PREVIEW === 'true'
const approved = ['Overview', 'New Analysis', 'Protocol Analysis',
  'Security Assessment', 'Findings', 'Reports']
const hidden = ['Security Associations', 'Encrypted Traffic AI', 'Compare Analyses',
  'Evidence Provenance', 'Threat Matrix', 'Testbed / Demo', 'System']

it.runIf(preview).each(['weak', 'strong'])('runs %s through the backend with loading and completion', async scenario => {
  let resolve!: (value: Response) => void
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise<Response>(r=>{resolve=r}))
  const complete = vi.fn()
  render(<NewAnalysis onComplete={complete}/>)
  expect(screen.getByText('Public preview supports the bundled synthetic fixture files only.')).toBeVisible()
  fireEvent.click(screen.getByRole('button', {name: scenario === 'weak' ? 'Analyze Weak VPN' : 'Analyze Strong VPN'}))
  expect(fetch).toHaveBeenCalledWith('/api/preview/demo/' + scenario, {method: 'POST'})
  for (const name of ['Analyze Weak VPN', 'Analyze Strong VPN']) expect(screen.getByRole('button', {name})).toBeDisabled()
  expect(screen.getByRole('status')).toHaveTextContent('Running protocol and security analysis…')
  expect(complete).not.toHaveBeenCalled()
  resolve(await response(analysis))
  await waitFor(()=>expect(complete).toHaveBeenCalledWith(analysis))
})

it.runIf(preview)('offers a first-open demo and selects the returned analysis on Overview', async () => {
  const demo = {...analysis, label: 'SYNTHETIC FIXTURE · Weak VPN Demo'}
  let created = false
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(input => {
    if (String(input) === '/api/preview/demo/weak') { created = true; return response(demo) }
    if (String(input) === '/api/analyses') return response(created ? [demo] : [])
    if (String(input) === '/api/health') return response({status: 'ok'})
    return response(demo)
  })
  render(<App/>)
  await screen.findByText('Try the interactive VPN assessment')
  expect(fetch.mock.calls.some(([url])=>String(url).includes('/preview/demo/'))).toBe(false)
  fireEvent.click(screen.getByRole('button', {name: 'Analyze Weak VPN'}))
  await screen.findByText('Demo analysis complete. Explore Protocol Analysis, Security Assessment, Findings and Reports.')
  expect(screen.getByRole('heading', {name: 'Overview', level: 1})).toBeVisible()
  await waitFor(()=>expect(screen.getByRole('combobox', {name: 'Selected analysis'})).toHaveValue(demo.analysis_id))
  expect(screen.getByText('An incomplete picture')).toBeVisible()
})

it.runIf(preview).each(['network', 'server'])('shows safe %s failure text and permits retry', async failure => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(()=>failure === 'network' ? Promise.reject(new Error('/private/path')) : response({detail: '/private/path'}, false))
  render(<NewAnalysis onComplete={vi.fn()}/>)
  fireEvent.click(screen.getByRole('button', {name: 'Analyze Weak VPN'}))
  expect(await screen.findByRole('alert')).toHaveTextContent('Demo service is temporarily unavailable. Please retry.')
  expect(screen.queryByText('/private/path')).not.toBeInTheDocument()
  expect(screen.getByRole('button', {name: 'Analyze Weak VPN'})).toBeEnabled()
  expect(screen.getByRole('button', {name: 'Analyze Strong VPN'})).toBeEnabled()
})

it('keeps normal navigation complete and preview navigation limited to six views', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(input => {
    if (String(input) === '/api/analyses') return response([{ ...analysis, capture_source: 'SYNTHETIC_FIXTURE' }])
    if (String(input) === '/api/health') return response({ status: 'ok' })
    if (String(input).endsWith('/hardening')) return response({ snippet: 'RECOMMENDATION' })
    return response({ ...analysis, capture_source: 'SYNTHETIC_FIXTURE' })
  })
  render(<App />)
  await screen.findByText('An incomplete picture')
  const nav = screen.getByRole('navigation')
  expect(nav.querySelectorAll('button')).toHaveLength(preview ? 6 : 13)
  for (const name of approved) expect(screen.getByRole('button', { name, hidden: false })).toBeVisible()
  for (const name of hidden) {
    if (preview) expect(nav.querySelector(`[aria-label="${name}"]`)).not.toBeInTheDocument()
    else expect(nav.querySelector(`[aria-label="${name}"]`)).toBeInTheDocument()
  }
  expect(screen.getByText(/SYNTHETIC FIXTURE · Bundled capture/)).toBeVisible()
  expect(screen.getByText(/Unknown checks receive no secure credit/)).toBeVisible()
  if (preview) expect(screen.queryByText('Encrypted traffic inference')).not.toBeInTheDocument()
  else expect(screen.getByText('Encrypted traffic inference')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Reports' }))
  await screen.findByText('RECOMMENDATION')
  expect(screen.getByRole('link', { name: /Download technical HTML/ })).toHaveAttribute(
    'href', `/api/analyses/${analysis.analysis_id}/report/technical`)
  if (preview) {
    expect(screen.getAllByText('SIH Submission Preview · Core Assessment Workflow')[0]).toBeVisible()
    expect(screen.getByText(/Preview analyses are temporary/)).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Download Analysis JSON' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Delete analysis' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'New Analysis' }))
    expect(screen.getByRole('link', { name: 'Weak capture' })).toHaveAttribute('href', '/fixtures/weak/weak.pcap')
    expect(screen.getByRole('link', { name: 'Strong capture' })).toHaveAttribute('href', '/fixtures/strong/strong.pcap')
    expect(screen.queryByRole('checkbox', { name: /Retain capture/ })).not.toBeInTheDocument()
  } else {
    expect(screen.getByRole('link', { name: 'Download Analysis JSON' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Delete analysis' })).toBeVisible()
  }
})
