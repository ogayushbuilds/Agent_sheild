import { useEffect, useState } from 'react'
import { api, type AuditEvent, type CheckActionResponse, type SimulatorAction, type SourceTrustLevel } from './api'
import { monitorApi, type Agent, type AgentCreate, type AgentDetail, type AgentAction, type AgentIncident, type AgentEnvironment } from './monitorApi'
import { Evidence, ScreenHeading, message } from './MonitorShared'
import { AgentSummary, AgentActionEvidence } from './AgentEvidence'

const actions: SimulatorAction[] = ['read_public_document', 'read_restricted_document', 'http_get', 'http_post', 'run_shell_command', 'send_email']
const domainPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/
function entries(value: string) { return value.split(/[\n,]/).map(item => item.trim()).filter(Boolean) }
export function validateAgent(value: AgentCreate): string {
  if (!value.name.trim() || !value.external_agent_id.trim() || !value.environment.trim()) return 'Name, external ID and environment are required.'
  if (value.name.length > 255 || value.external_agent_id.length > 255 || value.environment.length > 64 || value.description.length > 2000) return 'Agent fields exceed their maximum length.'
  for (const list of [value.allowed_tools, value.approved_domains]) {
    if (list.length > 100 || list.some(item => !item.trim() || item.length > 255) || new Set(list).size !== list.length) return 'Tools and domains must be unique, with at most 100 entries of 255 characters.'
  }
  if (value.approved_domains.some(domain => !domainPattern.test(domain))) return 'Approved domains must be exact DNS hostnames, such as example.com; no URLs or wildcards.'
  return ''
}

function AgentForm({ onCreated }: { onCreated: (agent: Agent) => void }) {
  const [name, setName] = useState(''); const [external, setExternal] = useState(''); const [environment, setEnvironment] = useState<AgentEnvironment>('development')
  const [description, setDescription] = useState(''); const [tools, setTools] = useState(''); const [domains, setDomains] = useState('')
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: React.FormEvent) {
    event.preventDefault()
    const value: AgentCreate = { name: name.trim(), external_agent_id: external.trim(), environment, description, allowed_tools: entries(tools), approved_domains: entries(domains).map(domain => domain.toLowerCase()) }
    const validation = validateAgent(value); setError(validation); if (validation) return
    setBusy(true)
    try { const created = await monitorApi.createAgent(value); onCreated(created); setName(''); setExternal(''); setDescription(''); setTools(''); setDomains('') } catch (error) { setError(message(error)) } finally { setBusy(false) }
  }
  return <form className="panel custom-form" onSubmit={submit} noValidate><h2>Register agent</h2>
    <div className="field"><label htmlFor="agent-name">Agent name</label><input id="agent-name" maxLength={255} value={name} onChange={e => setName(e.target.value)} /></div>
    <div className="field"><label htmlFor="agent-external">External agent ID</label><input id="agent-external" maxLength={255} value={external} onChange={e => setExternal(e.target.value)} /></div>
    <div className="field"><label htmlFor="agent-env">Environment</label><select id="agent-env" value={environment} onChange={e => setEnvironment(e.target.value as AgentEnvironment)}>{['development', 'staging', 'production'].map(value => <option key={value}>{value}</option>)}</select></div>
    <div className="field"><label htmlFor="agent-description">Description</label><textarea id="agent-description" maxLength={2000} value={description} onChange={e => setDescription(e.target.value)} /></div>
    <div className="field"><label htmlFor="agent-tools">Allowed tools (comma or newline separated)</label><textarea id="agent-tools" value={tools} onChange={e => setTools(e.target.value)} /></div>
    <div className="field"><label htmlFor="agent-domains">Approved domains (exact hostnames)</label><textarea id="agent-domains" value={domains} onChange={e => setDomains(e.target.value)} /></div>
    {error && <p className="form-error" role="alert">{error}</p>}<button className="button safe-action" disabled={busy}>{busy ? 'Registering…' : 'Register agent'}</button>
  </form>
}

function AgentSimulator({ agent, onChecked }: { agent: Agent; onChecked: () => void }) {
  const [session, setSession] = useState(''); const [action, setAction] = useState<SimulatorAction>('read_public_document'); const [tool, setTool] = useState('browser'); const [trust, setTrust] = useState<SourceTrustLevel>('untrusted'); const [args, setArgs] = useState('{"document":"public fixture"}')
  const [result, setResult] = useState<CheckActionResponse | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(''); setResult(null)
    let argumentsValue: unknown
    try { argumentsValue = JSON.parse(args) } catch { setError('Arguments must be valid JSON.'); return }
    if (!argumentsValue || Array.isArray(argumentsValue) || typeof argumentsValue !== 'object') { setError('Arguments must be a JSON object.'); return }
    if (!tool.trim() || tool.trim().length > 255 || session.trim().length > 36) { setError('Enter a tool name (up to 255 characters) and a session ID of at most 36 characters.'); return }
    setBusy(true)
    try {
      const sessionId = session.trim() || (await api.createSession(agent.external_agent_id)).id; setSession(sessionId)
      setResult(await api.checkAction({ agent_id: agent.external_agent_id, session_id: sessionId, action_type: action, tool_name: tool.trim(), source_trust_level: trust, arguments: argumentsValue as Record<string, unknown>, simulator_mode: true })); onChecked()
    } catch (error) { setError(message(error)) } finally { setBusy(false) }
  }
  return <form className="panel custom-form" onSubmit={submit}><h2>Check-only simulator</h2><p>Selected agent: {agent.name}. Only policy evaluation is submitted; no real tools are executed.</p>
    <div className="field"><label htmlFor="registry-session">Session ID (blank creates a session for this agent)</label><input id="registry-session" value={session} onChange={e => setSession(e.target.value)} maxLength={36} /></div>
    <div className="field-row"><div className="field"><label htmlFor="registry-action">Registered agent action</label><select id="registry-action" value={action} onChange={e => setAction(e.target.value as SimulatorAction)}>{actions.map(item => <option key={item}>{item}</option>)}</select></div><div className="field"><label htmlFor="registry-tool">Simulator tool name</label><input id="registry-tool" value={tool} maxLength={255} onChange={e => setTool(e.target.value)} /></div></div>
    <div className="field"><label htmlFor="registry-trust">Simulator source trust</label><select id="registry-trust" value={trust} onChange={e => setTrust(e.target.value as SourceTrustLevel)}>{['trusted', 'untrusted', 'user', 'system', 'unknown'].map(item => <option key={item}>{item}</option>)}</select></div>
    <div className="field"><label htmlFor="registry-args">Simulator arguments (JSON object)</label><textarea id="registry-args" value={args} onChange={e => setArgs(e.target.value)} rows={4} /></div>
    {error && <p role="alert" className="form-error">{error}</p>}<button className="button safe-action" disabled={busy}>{busy ? 'Checking…' : 'Check simulator action'}</button>
    {result && <div role="status" className="reason-box"><strong>{result.decision} · Risk {result.risk_score}/100 · {result.executed ? 'executed' : 'not executed'}</strong>{result.reasons.map((reason, i) => <p key={i}>{reason}</p>)}</div>}
  </form>
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]); const [selected, setSelected] = useState(''); const [loading, setLoading] = useState(true); const [listError, setListError] = useState('')
  const [detail, setDetail] = useState<AgentDetail | null>(null); const [actionsFeed, setActions] = useState<AgentAction[]>([]); const [incidents, setIncidents] = useState<AgentIncident[]>([]); const [audit, setAudit] = useState<AuditEvent[]>([])
  const [detailError, setDetailError] = useState(''); const [revision, setRevision] = useState(0); const [busy, setBusy] = useState(false)
  async function load() { setLoading(true); setListError(''); try { setAgents((await monitorApi.agents()).agents) } catch (error) { setListError(message(error)) } finally { setLoading(false) } }
  useEffect(() => { void load() }, [])
  useEffect(() => {
    let cancelled = false; setDetail(null); setDetailError('')
    if (selected) Promise.all([monitorApi.agent(selected), monitorApi.actions(selected), monitorApi.incidents(selected), monitorApi.audit(selected)]).then(([agent, actionResult, incidentResult, auditResult]) => {
      if (!cancelled) { setDetail(agent); setActions(actionResult.actions); setIncidents(incidentResult.incidents); setAudit(auditResult.events) }
    }).catch(error => { if (!cancelled) setDetailError(message(error)) })
    return () => { cancelled = true }
  }, [selected, revision])
  async function toggle() {
    if (!detail) return; setBusy(true)
    try { const agent = await monitorApi.status(detail.id, detail.status === 'paused' ? 'resume' : 'pause'); setAgents(items => items.map(item => item.id === agent.id ? agent : item)); setRevision(value => value + 1) } catch (error) { setDetailError(message(error)) } finally { setBusy(false) }
  }
  const selectedAgent = agents.find(agent => agent.id === selected)
  return <><ScreenHeading title="Agents" detail="Register agents and inspect recorded policy checks, incidents and audit evidence." /><div className="custom-grid"><AgentForm onCreated={agent => { setAgents(items => [...items, agent]); setSelected(agent.id) }} /><section className="panel"><div className="panel-heading"><h2>Registered agents</h2><button className="button ghost" onClick={load} disabled={loading}>Refresh agents</button></div>
    {loading ? <p role="status">Loading agents…</p> : listError ? <p role="alert" className="form-error">{listError}</p> : !agents.length ? <p>No registered agents yet.</p> : <div className="agent-list">{agents.map(agent => <button key={agent.id} className={`agent-choice ${selected === agent.id ? 'selected' : ''}`} onClick={() => setSelected(agent.id)} aria-pressed={selected === agent.id}><strong>{agent.name}</strong><span>{agent.environment} · {agent.status}</span><small>{agent.external_agent_id}</small></button>)}</div>}
  </section></div>
    {selected && <div className="agent-detail">{detailError && <p role="alert" className="form-error">{detailError}<button className="button ghost" onClick={() => setRevision(value => value + 1)}>Retry details</button></p>}{!detail && !detailError && <p role="status">Loading agent detail…</p>}{detail && <><section className="panel"><div className="panel-heading"><div><h2>{detail.name}</h2><p>Status: {detail.status}</p></div><button className="button ghost" disabled={busy || detail.status === 'disabled'} onClick={toggle}>{detail.status === 'paused' ? 'Resume agent' : 'Pause agent'}</button></div><p>{detail.description}</p><p>Tools: {detail.allowed_tools.join(', ') || 'None'} · Domains: {detail.approved_domains.join(', ') || 'None'}</p><AgentSummary metrics={detail.metrics} /></section>
      <section className="panel evidence-list"><h2>Actions</h2>{!actionsFeed.length && <p>No actions recorded. Submit a check-only simulator action below.</p>}{actionsFeed.map(action => <AgentActionEvidence key={action.id} action={action} />)}</section>
      <section className="panel evidence-list"><h2>Incidents</h2>{!incidents.length && <p>No incidents recorded.</p>}{incidents.map(incident => <article key={incident.id}><strong>{incident.severity} · {incident.decision}</strong><p>{incident.reasons.join(' · ')}</p></article>)}</section><Evidence title="Audit events" items={audit} /></>}
      {selectedAgent && <AgentSimulator key={selected} agent={selectedAgent} onChecked={() => setRevision(value => value + 1)} />}
    </div>}
  </>
}
