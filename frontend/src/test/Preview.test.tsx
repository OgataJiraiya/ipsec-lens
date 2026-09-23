import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import App from '../App'
import { analysis, response } from './fixtures'

const preview = import.meta.env.VITE_SUBMISSION_PREVIEW === 'true'
const approved = ['Overview', 'New Analysis', 'Protocol Analysis',
  'Security Assessment', 'Findings', 'Reports']
const hidden = ['Security Associations', 'Encrypted Traffic AI', 'Compare Analyses',
  'Evidence Provenance', 'Threat Matrix', 'Testbed / Demo', 'System']

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
