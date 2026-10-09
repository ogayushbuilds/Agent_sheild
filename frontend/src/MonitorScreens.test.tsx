import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import Agents from './Agents'
import MonitorChat from './MonitorChat'
import App from './App'
import { validateAgent } from './Agents'
import { validateChat } from './MonitorChat'
import { type Agent, type AgentMetrics, type AgentAction } from './monitorApi'
import { AgentSummary, AgentActionEvidence } from './AgentEvidence'
import ApiAccess from './ApiAccess'
import { api, setApiKey } from './api'

const agent: Agent = { id: 'registered-1', name: 'Research agent', external_agent_id: 'research-ext', environment: 'development', description: 'Research checks', allowed_tools: ['browser'], approved_domains: ['example.com'], status: 'active', created_at: '2026-01-01', updated_at: '2026-01-01' }
const metrics: AgentMetrics = { actions: 7, incidents: 2, blocked: 1, approval_required: 1, allowed: 5, prompt_injection_incidents: 1, sensitive_data_incidents: 2, average_risk_score: 42.125, pending_approvals: 1, last_activity_timestamp: '2026-10-08T10:15:00Z' }
const recordedAction: AgentAction = { id: 'recorded-1', agent_id: agent.external_agent_id, session_id: 'agent-session', tool_name: 'browser', action_type: 'http_post', decision: 'block', risk_score: 90, reasons: ['Recorded policy reason'], arguments: {}, timestamp: '2026-10-08T10:15:00Z', prompt_injection: { detected: true, indicators: ['instruction_override'], confidence: 0.9 }, sensitive_data: { detected: false, categories: [], redacted_preview: '[REDACTED] <b>text</b>' }, matched_policies: ['destination_allowlist'] }
const session = { id: 'chat-1', source_type: 'pasted_text', url: null, metadata: {}, status: 'created', created_at: '2026-01-01' }
const shareUrl = 'https://chatgpt.com/share/12345678-1234-1234-1234-123456789abc'
const analysis = { session: { ...session, status: 'evaluated' }, status: 'evaluated', limitation: null, findings: [{ detector: 'sensitive_data', detected: true, indicators: [], categories: ['secret'], severity: 'high', confidence: 1, reasons: [], redacted_preview: '[REDACTED] <b>plain text</b>' }], urls_detected: [], tool_call_instructions_detected: true, redacted_preview: '[REDACTED] <b>plain text</b>', risk_score: 50, source_trust_level: 'untrusted', executed: false }
const response = (body: unknown, ok = true) => Promise.resolve({ ok, status: ok ? 200 : 503, json: async () => body, text: async () => String(body) } as Response)

describe('live monitor screens', () => {
  let status = 'active'
  beforeEach(() => {
    status = 'active'
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/health')) return response({ status: 'ok' })
      if (url.endsWith('/approvals')) return response({ approvals: [] })
      if (url.endsWith('/api/v1/agents')) return response(init?.method === 'POST' ? agent : { agents: [agent] })
      if (url.endsWith('/pause')) { status = 'paused'; return response({ ...agent, status }) }
      if (url.endsWith('/resume')) { status = 'active'; return response({ ...agent, status }) }
      if (url.endsWith('/agents/registered-1')) return response({ ...agent, status, metrics })
      if (url.endsWith('/actions')) return response({ actions: [] })
      if (url.endsWith('/incidents')) return response({ incidents: [] })
      if (url.endsWith('/audit-events')) return response({ events: [{ id: 'audit-1', event_type: 'created', payload: {} }] })
      if (url.endsWith('/chat-monitor/sessions')) return response(session)
      if (url.endsWith('/analyze')) return response(analysis)
      if (url.endsWith('/events')) return response({ events: [{ id: 'event-1', sequence: 1, event_type: 'transcript_analyzed', redacted_text: '[REDACTED]', payload: { executed: false } }] })
      if (url.endsWith('/sessions')) return response({ id: 'agent-session', agent_id: agent.external_agent_id })
      if (url.endsWith('/check-action')) return response({ action_request_id: 'action-1', decision: 'block', risk_score: 90, reasons: ['Domain rejected'], executed: false, source_trust_level: 'untrusted' })
      throw new Error(`Unexpected URL: ${url}`)
    }))
  })
  afterEach(() => { setApiKey(''); vi.unstubAllGlobals(); vi.unstubAllEnvs() })

  it('validates required agent fields before registration', async () => {
    render(<Agents />)
    fireEvent.click(screen.getByRole('button', { name: 'Register agent' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('required')
    expect(fetch).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ method: 'POST' }))
  })
  it('exposes Agents and Monitor Chat through responsive workspace navigation', async () => {
    render(<App />)
    fireEvent.change(screen.getByLabelText('Workspace navigation'), { target: { value: 'agents' } })
    expect(await screen.findByRole('heading', { name: 'Agents' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Workspace navigation'), { target: { value: 'monitor-chat' } })
    expect(screen.getByRole('heading', { name: 'Monitor Chat' })).toBeInTheDocument()
    expect(screen.getByText(/No hidden tool monitoring/)).toBeInTheDocument()
  })
  it('validates duplicate tools and exact domains', () => {
    expect(validateAgent({ ...agent, allowed_tools: ['browser', 'browser'] })).toContain('unique')
    expect(validateAgent({ ...agent, approved_domains: ['https://example.com'] })).toContain('exact DNS')
  })
  it('registers trimmed fields and normalized domains, then opens real detail metrics', async () => {
    render(<Agents />)
    fireEvent.change(screen.getByLabelText('Agent name'), { target: { value: ' Research agent ' } })
    fireEvent.change(screen.getByLabelText('External agent ID'), { target: { value: 'research-ext' } })
    fireEvent.change(screen.getByLabelText(/Allowed tools/), { target: { value: 'browser, http_get' } })
    fireEvent.change(screen.getByLabelText(/Approved domains/), { target: { value: 'EXAMPLE.com' } })
    fireEvent.click(screen.getByRole('button', { name: 'Register agent' }))
    expect(await screen.findByText('7')).toBeInTheDocument()
    const call = vi.mocked(fetch).mock.calls.find(([url, init]) => String(url).endsWith('/agents') && init?.method === 'POST')
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ name: 'Research agent', external_agent_id: 'research-ext', allowed_tools: ['browser', 'http_get'], approved_domains: ['example.com'] })
  })
  it('loads details and permits pause followed by resume', async () => {
    render(<Agents />)
    fireEvent.click(await screen.findByRole('button', { name: /Research agent/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Pause agent' }))
    expect(await screen.findByText('Status: paused')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Resume agent' }))
    expect(await screen.findByText('Status: active')).toBeInTheDocument()
    expect(screen.getByText('No incidents recorded.')).toBeInTheDocument()
  })
  it('checks an action for the selected external ID and session without execution', async () => {
    render(<Agents />)
    fireEvent.click(await screen.findByRole('button', { name: /Research agent/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Check simulator action' }))
    expect(await screen.findByText('Domain rejected')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/check-action'), expect.objectContaining({ body: expect.stringContaining('"agent_id":"research-ext"') }))
    const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).endsWith('/check-action'))
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ session_id: 'agent-session', simulator_mode: true })
    expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes('execute-action'))).toBe(false)
  })
  it('shows registry loading, empty and request failure states', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response({ agents: [] })))
    render(<Agents />)
    expect(screen.getByRole('status')).toHaveTextContent('Loading agents')
    expect(await screen.findByText('No registered agents yet.')).toBeInTheDocument()
    vi.stubGlobal('fetch', vi.fn(() => response('Registry unavailable', false)))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh agents' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Registry unavailable')
  })
  it('surfaces pause failures and retains the current status', async () => {
    render(<Agents />)
    fireEvent.click(await screen.findByRole('button', { name: /Research agent/ }))
    await screen.findByRole('button', { name: 'Pause agent' })
    vi.stubGlobal('fetch', vi.fn(() => response('Status update failed', false)))
    fireEvent.click(screen.getByRole('button', { name: 'Pause agent' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Status update failed')
    expect(screen.getByText('Status: active')).toBeInTheDocument()
  })
  it('rejects blank transcripts and malformed URLs before sending', async () => {
    render(<MonitorChat />)
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('alert')).toHaveTextContent('non-empty transcript')
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: 'file:///secret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('alert')).toHaveTextContent('public HTTP(S)')
    expect(fetch).not.toHaveBeenCalled()
    expect(validateChat('', 'pasted_text', 'é'.repeat(65537))).toContain('128 KiB')
  })
  it('analyzes untrusted text and renders only returned redacted evidence as text', async () => {
    const { container } = render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText(/Transcript text/), { target: { value: 'raw-sensitive-input' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByText('Status: evaluated')).toBeInTheDocument()
    expect(screen.getAllByText('[REDACTED] <b>plain text</b>')).toHaveLength(2)
    expect(container.querySelector('.redacted-preview b')).toBeNull()
    expect(screen.queryByDisplayValue('raw-sensitive-input')).not.toBeInTheDocument()
    expect(await screen.findByText('1 · transcript_analyzed')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/analyze'), expect.objectContaining({ body: '{"pasted_text":"raw-sensitive-input"}' }))
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }))
    expect(screen.getByText('Status: not started')).toBeInTheDocument()
    expect(screen.queryByText('Risk: 50/100')).not.toBeInTheDocument()
  })
  it('warns metadata-only users, omits transcript and shows not-evaluated limitation', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/sessions')) return response({ ...session, source_type: 'metadata_only', status: 'not_evaluated' })
      if (url.endsWith('/analyze')) return response({ ...analysis, status: 'not_evaluated', session: { ...session, source_type: 'metadata_only', status: 'not_evaluated' }, risk_score: null, limitation: 'URL metadata was not fetched; no connector is configured.', findings: [], redacted_preview: '' })
      return response({ events: [] })
    }))
    render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'metadata_only' } })
    expect(screen.getByRole('note')).toHaveTextContent('No transcript can be evaluated')
    expect(screen.queryByLabelText(/Transcript text/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('alert')).toHaveTextContent('URL is required')
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: 'https://example.com/chat' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByText('Risk: Not evaluated')).toBeInTheDocument()
    expect(screen.getByText('URL metadata was not fetched; no connector is configured.')).toBeInTheDocument()
    const bodies = vi.mocked(fetch).mock.calls.map(([, init]) => init?.body).filter(Boolean)
    expect(bodies.every(body => !String(body).includes('pasted_text'))).toBe(true)
  })
  it('accepts only exact public ChatGPT UUID links with explicit consent', () => {
    expect(validateChat(shareUrl, 'chatgpt_share', '', true)).toBe('')
    expect(validateChat(shareUrl, 'chatgpt_share', '')).toContain('Consent is required')
    for (const url of ['', shareUrl.replace('https:', 'http:'), shareUrl.replace('chatgpt.com', 'chat.openai.com'), shareUrl.replace('chatgpt.com', 'chatgpt.com.evil.com'), shareUrl.replace('chatgpt.com', 'user@chatgpt.com'), shareUrl.replace('chatgpt.com', 'chatgpt.com:443'), `${shareUrl}?x=1`, `${shareUrl}#`, `${shareUrl}/`, shareUrl.replace('123456789abc', 'bad'), shareUrl.replace('/share/', '/c/'), shareUrl.replace('/share/', '/share/%31'), shareUrl.replace('/share/', '/other/../share/')]) {
      expect(validateChat(url, 'chatgpt_share', '', true)).toContain('exact public HTTPS')
    }
  })
  it('blocks public share submission until consent and clears consent on URL or mode changes', () => {
    render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'chatgpt_share' } })
    expect(screen.queryByText(/No URL is fetched/)).not.toBeInTheDocument()
    expect(screen.getByText(/Private links and logins are not supported/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Transcript text/)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Provider (metadata only)')).toHaveValue('openai')
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: shareUrl } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Consent is required')
    expect(fetch).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: `${shareUrl}?query` } })
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(screen.getByRole('alert')).toHaveTextContent('exact public HTTPS')
    expect(fetch).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'pasted_text' } })
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'chatgpt_share' } })
    expect(screen.getByRole('checkbox')).not.toBeChecked()
  })
  it('imports a public share through backend-only requests and displays redacted analysis', async () => {
    const originalFetch = fetch
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/chat-monitor/sessions')) return response({ ...session, source_type: 'chatgpt_share', url: shareUrl, metadata: { provider: 'openai' } })
      if (String(input).endsWith('/analyze')) return response({ ...analysis, session: { ...analysis.session, source_type: 'chatgpt_share', url: shareUrl } })
      return originalFetch(input, init)
    }))
    const { container } = render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'chatgpt_share' } })
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: shareUrl } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByText('Status: evaluated')).toBeInTheDocument()
    expect(screen.getByText('Session: chat-1 · chatgpt_share')).toBeInTheDocument()
    expect(screen.getAllByText('[REDACTED] <b>plain text</b>')).toHaveLength(2)
    expect(container.querySelector('.redacted-preview b')).toBeNull()
    await screen.findByText('1 · transcript_analyzed')
    const calls = vi.mocked(fetch).mock.calls
    const created = calls.find(([url]) => String(url).endsWith('/chat-monitor/sessions'))
    expect(JSON.parse(String(created?.[1]?.body))).toEqual({ source_type: 'chatgpt_share', url: shareUrl, metadata: { provider: 'openai' } })
    const analyzed = calls.find(([url]) => String(url).endsWith('/analyze'))
    expect(JSON.parse(String(analyzed?.[1]?.body))).toEqual({ fetch_consent: true })
    expect(calls.every(([url]) => String(url).includes('/api/v1/chat-monitor/'))).toBe(true)
    expect(calls.some(([url]) => String(url).startsWith('https://chatgpt.com'))).toBe(false)
  })
  it('shows honest public fetch failures and offers a working pasted-text fallback', async () => {
    const originalFetch = fetch
    let failed = false
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/analyze') && !failed) { failed = true; return response('Public share unavailable; login-required pages cannot be imported.', false) }
      return originalFetch(input, init)
    }))
    render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText('Access mode'), { target: { value: 'chatgpt_share' } })
    fireEvent.change(screen.getByLabelText(/Chat URL/), { target: { value: shareUrl } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Public share unavailable')
    expect(screen.queryByText('Risk: 50/100')).not.toBeInTheDocument()
    expect(screen.getByText('Status: request failed')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Use pasted text instead' }))
    expect(screen.getByLabelText('Access mode')).toHaveValue('pasted_text')
    fireEvent.change(screen.getByLabelText(/Transcript text/), { target: { value: 'fallback transcript' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByText('Status: evaluated')).toBeInTheDocument()
    expect(fetch).toHaveBeenLastCalledWith(expect.stringContaining('/audit-events'), expect.anything())
    const calls = vi.mocked(fetch).mock.calls.filter(([url]) => String(url).endsWith('/analyze'))
    expect(JSON.parse(String(calls[1][1]?.body))).toEqual({ pasted_text: 'fallback transcript' })
  })
  it('shows analysis failures and re-enables submission', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response('Analysis unavailable', false)))
    render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText(/Transcript text/), { target: { value: 'hello' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Analysis unavailable')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Analyze' })).toBeEnabled())
  })
  it('surfaces registration conflicts without clearing entered fields', async () => {
    vi.stubGlobal('fetch', vi.fn((_input: RequestInfo | URL, init?: RequestInit) => init?.method === 'POST' ? response('Agent already exists', false) : response({ agents: [] })))
    render(<Agents />)
    fireEvent.change(screen.getByLabelText('Agent name'), { target: { value: 'Duplicate' } })
    fireEvent.change(screen.getByLabelText('External agent ID'), { target: { value: 'duplicate-ext' } })
    fireEvent.click(screen.getByRole('button', { name: 'Register agent' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Agent already exists')
    expect(screen.getByLabelText('Agent name')).toHaveValue('Duplicate')
  })
  it('retains analysis evidence when event retrieval fails', async () => {
    const existingFetch = fetch
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/events') ? response('Events unavailable', false) : existingFetch(input, init)))
    render(<MonitorChat />)
    fireEvent.change(screen.getByLabelText(/Transcript text/), { target: { value: 'hello' } })
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Analysis returned, but events could not be loaded')
    expect(screen.getByText('Risk: 50/100')).toBeInTheDocument()
  })
  it('shows all enriched summary cards and last activity from the API', async () => {
    render(<Agents />)
    fireEvent.click(await screen.findByRole('button', { name: /Research agent/ }))
    await screen.findByText('Actions inspected')
    for (const label of ['Allowed actions', 'Blocked actions', 'Prompt-injection incidents', 'Sensitive-data incidents', 'Average risk score', 'Pending approvals']) expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.getByText('42.13')).toBeInTheDocument()
    expect(screen.getByText(`Last activity: ${new Date(metrics.last_activity_timestamp!).toLocaleString()}`)).toBeInTheDocument()
  })
  it('makes absent last activity explicit without inventing a timestamp', () => {
    render(<AgentSummary metrics={{ ...metrics, last_activity_timestamp: null }} />)
    expect(screen.getByText('Last activity: No recorded activity')).toBeInTheDocument()
  })
  it('shows stored action detector evidence and matched policies safely', async () => {
    const originalFetch = fetch
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => String(input).endsWith('/actions') ? response({ actions: [recordedAction] }) : originalFetch(input, init)))
    const { container } = render(<Agents />)
    fireEvent.click(await screen.findByRole('button', { name: /Research agent/ }))
    expect(await screen.findByText('Detection status: Detected')).toBeInTheDocument()
    expect(screen.getByText('Detection status: Not detected')).toBeInTheDocument()
    expect(screen.getByText('destination_allowlist')).toBeInTheDocument()
    expect(screen.getByText(/instruction_override/)).toBeInTheDocument()
    expect(container.querySelector('.evidence-list pre b')).toBeNull()
  })
  it('labels null historical findings as unknown rather than clean', () => {
    render(<AgentActionEvidence action={{ ...recordedAction, prompt_injection: null, sensitive_data: null, matched_policies: [] }} />)
    expect(screen.getAllByText('Historical detector evidence unavailable; detection status is unknown.')).toHaveLength(2)
    expect(screen.queryByText('Detection status: Not detected')).not.toBeInTheDocument()
    expect(screen.getByText('No stored matched policies returned.')).toBeInTheDocument()
  })
  it('ignores build-time keys and sends only user-entered in-memory keys until cleared', async () => {
    vi.stubEnv('VITE_AGENTSHIELD_API_KEY', 'must-not-be-used')
    await api.health()
    expect(vi.mocked(fetch).mock.lastCall?.[1]?.headers).not.toHaveProperty('x-agentshield-api-key')
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem')
    render(<ApiAccess />)
    fireEvent.change(screen.getByLabelText('Backend API key'), { target: { value: 'local-entered-key' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply key' }))
    expect(screen.getByLabelText('Backend API key')).toHaveValue('')
    expect(screen.getByText('Key configured for this page session.')).toBeInTheDocument()
    await api.health()
    expect(vi.mocked(fetch).mock.lastCall?.[1]?.headers).toHaveProperty('x-agentshield-api-key', 'local-entered-key')
    expect(storageSpy).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Clear key' }))
    await api.health()
    expect(vi.mocked(fetch).mock.lastCall?.[1]?.headers).not.toHaveProperty('x-agentshield-api-key')
    storageSpy.mockRestore()
  })
})
