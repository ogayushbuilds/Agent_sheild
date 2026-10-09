import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const jsonResponse = (body: unknown) => Promise.resolve({
  ok: true,
  status: 200,
  json: () => Promise.resolve(body),
  text: () => Promise.resolve(''),
} as Response)

const attackTrace = {
  trace_id: 'test-trace', scenario: 'attack', simulator_mode: true,
  final_decision: 'block', explanation: 'The simulated attack was blocked by policy.',
  events: [{
    sequence: 1, event_id: 'event-1', event_type: 'tool_call',
    description: 'Attempted upload to an unapproved destination', risk_score: 95,
    decision: 'block',
    tool_call: { tool_name: 'http_post', action_type: 'http_post', arguments: {}, executed: false },
    detector_findings: [], policy_matches: ['Destination allowlist'], reasons: ['Destination is not approved'],
  }],
}

describe('AgentShield dashboard', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/health')) return jsonResponse({ status: 'ok', service: 'agentshield-backend' })
      if (url.endsWith('/api/v1/approvals')) return jsonResponse({ approvals: [] })
      if (url.endsWith('/api/v1/demo/attack-run')) return jsonResponse(attackTrace)
      throw new Error(`Unexpected request: ${url}`)
    }))
  })

  afterEach(() => vi.unstubAllGlobals())

  it('renders local simulator controls and the empty approval state', async () => {
    render(<App />)
    expect(screen.getByRole('button', { name: /run safe scenario/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run attack scenario/i })).toBeInTheDocument()

    await waitFor(() => expect(screen.getByText('API connected')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /approval queue/i }))
    expect(await screen.findByText('No actions need review')).toBeInTheDocument()
    expect(screen.getByText('The live approval endpoint returned an empty queue.')).toBeInTheDocument()
  })

  it('loads and displays a mocked attack demo response without external network access', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /run attack scenario/i }))
    expect(await screen.findByText('Attack contained by policy')).toBeInTheDocument()
    expect(screen.getByText('Proof: attacker destination was not contacted')).toBeInTheDocument()
    expect(screen.getByText('Step 0 of 1')).toBeInTheDocument()
  })

  it('renders the custom action form with the restricted simulator action set', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /custom action test/i }))
    expect(await screen.findByRole('heading', { name: 'Custom action test' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /simulator action/i })).toHaveValue('read_public_document')
    expect(screen.getByText(/no real execution/i)).toBeInTheDocument()
  })

  it('shows backend risk factors and policy evidence in the cockpit after replay', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/health')) return jsonResponse({ status: 'ok' })
      if (url.endsWith('/api/v1/approvals')) return jsonResponse({ approvals: [] })
      if (url.endsWith('/api/v1/demo/attack-run')) return jsonResponse({ ...attackTrace, events: [{ ...attackTrace.events[0], risk_factors: [{ name: 'external_upload', weight: 35, reason: 'External upload' }], tool_call: { ...attackTrace.events[0].tool_call, arguments: { token: 'never-show-this-secret' } } }] })
      throw new Error(`Unexpected request: ${url}`)
    }))
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Security operations cockpit' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /run attack scenario/i }))
    await screen.findByText('Attack contained by policy')
    fireEvent.click(screen.getByRole('button', { name: /overview/i }))
    expect(screen.getByText('external upload')).toBeInTheDocument()
    expect(screen.getByText('35')).toBeInTheDocument()
    expect(screen.getByText('Destination is not approved')).toBeInTheDocument()
    expect(screen.queryByText(/never-show-this-secret/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^blocked$/i }))
    expect(screen.getByRole('button', { pressed: true })).toHaveTextContent('Attempted upload')
  })

  it('renders real pending approval evidence and routes to review', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/health')) return jsonResponse({ status: 'ok' })
      if (url.endsWith('/api/v1/approvals')) return jsonResponse({ approvals: [{ id: 'approval-real', action_request_id: 'action-real', status: 'pending', risk_score: 70, reasons: ['Human decision required'], policy_context: { policy_matches: ['Approval gate'] }, created_at: '2026-10-09T00:00:00Z', expires_at: '2026-10-10T00:00:00Z', action: { agent_id: 'agent-real', tool_name: 'browser', action_type: 'http_post', arguments: { password: 'hidden-password' } } }] })
      throw new Error(`Unexpected request: ${url}`)
    }))
    render(<App />)
    expect(await screen.findByText('Agent: agent-real')).toBeInTheDocument()
    expect(screen.getByText('Human decision required')).toBeInTheDocument()
    expect(screen.queryByText(/hidden-password/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /approval queue/i }))
    expect(await screen.findByRole('button', { name: /^approve$/i })).toBeInTheDocument()
  })

  it('rejects malformed JSON before making a gateway request', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /custom action test/i }))
    fireEvent.change(await screen.findByLabelText(/action arguments/i), { target: { value: '{bad' } })
    fireEvent.click(screen.getByRole('button', { name: /evaluate custom action/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/valid JSON/i)
    expect(fetch).not.toHaveBeenCalledWith(expect.stringContaining('/api/v1/check-action'), expect.anything())
  })

  it('creates a demo session and displays a mocked blocked custom action', async () => {
    window.localStorage.clear()
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/health')) return jsonResponse({ status: 'ok' })
      if (url.endsWith('/api/v1/approvals')) return jsonResponse({ approvals: [] })
      if (url.endsWith('/sessions')) return jsonResponse({ id: 'session-test', agent_id: 'custom-action-demo', metadata: {}, created_at: new Date().toISOString() })
      if (url.endsWith('/api/v1/check-action')) return jsonResponse({ action_request_id: 'action-test', decision: 'block', risk_score: 96, reasons: ['Restricted document access is blocked'], source_trust_level: 'user', executed: false, result: null })
      throw new Error(`Unexpected request: ${url}`)
    }))
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: /custom action test/i }))
    fireEvent.change(await screen.findByLabelText(/action arguments/i), { target: { value: '{"document":"patient-report"}' } })
    fireEvent.click(screen.getByRole('button', { name: /evaluate custom action/i }))
    expect(await screen.findByText('Restricted document access is blocked')).toBeInTheDocument()
    expect(screen.getByText('block')).toBeInTheDocument()
    expect(screen.getByText(/not executed/)).toBeInTheDocument()
  })
})
