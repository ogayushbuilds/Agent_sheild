import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, Approval, AuditEvent, CheckActionResponse, DemoTrace, DetectorFinding, SimulatorAction, SourceTrustLevel, TraceEvent } from './api'
import Agents from './Agents'
import MonitorChat from './MonitorChat'
import ApiAccess from './ApiAccess'

type View = 'cockpit' | 'overview' | 'activity' | 'trace' | 'approvals' | 'policy' | 'audit' | 'custom-action' | 'agents' | 'monitor-chat'
type LoadState = 'loading' | 'ready' | 'error'

const nav: { id: View; label: string; icon: string }[] = [
  { id: 'agents', label: 'Agents', icon: '◇' }, { id: 'monitor-chat', label: 'Monitor Chat', icon: '▱' },
  { id: 'cockpit', label: 'Overview', icon: '⌂' }, { id: 'custom-action', label: 'Custom action test', icon: '⚡' }, { id: 'activity', label: 'Live activity', icon: '◉' },
  { id: 'trace', label: 'Scenario playback', icon: '⌁' }, { id: 'approvals', label: 'Approval queue', icon: '✓' }, { id: 'policy', label: 'Policy', icon: '▤' }, { id: 'audit', label: 'Audit forensics', icon: '⌬' },
]
const policyCatalog = [
  ['Prompt injection defense', 'Untrusted webpage content cannot override agent instructions or authorize tools.'],
  ['Restricted document access', 'Confidential and restricted documents require explicit approval or are blocked.'],
  ['Sensitive data egress', 'Detected secrets and sensitive fields are redacted before external destinations are considered.'],
  ['Destination allowlist', 'External uploads are limited to approved destination domains; unknown domains are blocked.'],
  ['Tool execution boundary', 'Actions are checked before execution and simulator requests remain non-executing.'],
  ['Approval gate', 'High-risk actions can pause for an explicit human decision before execution.'],
  ['Audit trail', 'Session activity is recorded for investigation through the audit-events API.'],
]

function formatTime(value?: string) { return value ? new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—' }
function riskTone(score: number): 'green' | 'amber' | 'red' { return score >= 80 ? 'red' : score >= 40 ? 'amber' : 'green' }
function StatusPill({ children, tone = 'green' }: { children: React.ReactNode; tone?: 'green' | 'amber' | 'red' | 'blue' }) { return <span className={`pill pill-${tone}`}><i />{children}</span> }
function Empty({ title, detail }: { title: string; detail: string }) { return <div className="empty"><div className="empty-icon">◌</div><h3>{title}</h3><p>{detail}</p></div> }
function Loading({ text }: { text: string }) { return <div className="loading"><span className="spinner" />{text}</div> }
function SectionHeading({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail?: string; action?: React.ReactNode }) { return <div className="section-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{detail && <p>{detail}</p>}</div>{action}</div> }
function Metric({ icon, tone, value, label, source }: { icon: string; tone: string; value: number | string; label: string; source: string }) { return <div className="stat-card"><span className={`stat-icon ${tone}`}>{icon}</span><div><strong>{value}</strong><small>{label}</small><em>{source}</em></div></div> }

function ActivityRow({ event, expanded = false }: { event: TraceEvent; expanded?: boolean }) {
  const tone = event.decision === 'block' ? 'red' : event.risk_score >= 40 ? 'amber' : 'green'
  return <div className={`activity-row ${expanded ? 'expanded' : ''}`}><div className={`activity-dot ${tone}`} /><div className="activity-main"><div><strong>{event.description}</strong><small>{event.event_type.replace(/_/g, ' ')} · {event.event_id}</small></div><div className="activity-right"><StatusPill tone={tone}>{event.decision}</StatusPill><span>{event.risk_score ? `Risk ${event.risk_score}` : 'Observed'}</span></div>{expanded && (event.reasons.length > 0 || event.policy_matches.length > 0) && <div className="activity-detail">{event.reasons.join(' · ')}{event.policy_matches.length > 0 && <><br /><b>Matched rules:</b> {event.policy_matches.join(', ')}</>}</div>}</div></div>
}

function FindingPreview({ finding }: { finding: DetectorFinding }) {
  if (!finding.detected && !finding.redacted_preview) return null
  return <div className="finding"><div><StatusPill tone="red">{finding.detector.replace(/_/g, ' ')}</StatusPill><span className="finding-confidence">{Math.round(finding.confidence * 100)}% confidence</span></div><code>{String(finding.redacted_preview || finding.reasons.join(' · ') || 'Detection matched')}</code></div>
}

function Playback({ trace, visibleCount }: { trace: DemoTrace; visibleCount: number }) {
  const events = trace.events.slice(0, visibleCount)
  return <div className="playback"><div className="playback-progress"><span style={{ width: `${Math.round((visibleCount / trace.events.length) * 100)}%` }} /></div><div className="playback-count">Step {Math.min(visibleCount, trace.events.length)} of {trace.events.length}</div><div className="trace-wrap"><div className="trace-line" />{events.map((event, index) => <div className="trace-step" key={event.event_id}><div className={`trace-node ${event.decision === 'block' ? 'node-red' : event.risk_score >= 40 ? 'node-amber' : 'node-green'}`}>{String(index + 1).padStart(2, '0')}</div><div className="trace-card"><div className="trace-card-top"><span className="eyebrow">Event {String(index + 1).padStart(2, '0')}</span><StatusPill tone={event.decision === 'block' ? 'red' : event.risk_score >= 40 ? 'amber' : 'green'}>{event.decision}</StatusPill></div><h3>{event.description}</h3><p>{event.event_type.replace(/_/g, ' ')}</p>{event.risk_score > 0 && <div className="risk-readout"><strong>Risk score {event.risk_score}/100</strong><span>{riskTone(event.risk_score)} risk</span></div>}{event.policy_matches.length > 0 && <div className="match-list"><b>Exact matched policy rules</b>{event.policy_matches.map((rule) => <span key={rule}>✓ {rule}</span>)}</div>}{event.detector_findings.map((finding, findingIndex) => <FindingPreview finding={finding} key={`${event.event_id}-${finding.detector}-${findingIndex}`} />)}</div>{index < events.length - 1 && <div className="trace-arrow">↓</div>}</div>)}</div></div>
}

function ApprovalCard({ approval, onReview, busy }: { approval: Approval; onReview: (id: string, decision: 'approve' | 'deny') => void; busy: boolean }) {
  return <article className="approval-card"><div className="approval-top"><div className="approval-tool"><span className="tool-icon">⌘</span><div><h3>{approval.action.tool_name}<span> / {approval.action.action_type}</span></h3><p>{approval.action.source_trust_level || 'unknown'} source · requested {formatTime(approval.created_at)}</p></div></div><StatusPill tone={riskTone(approval.risk_score)}>Risk {approval.risk_score}</StatusPill></div><div className="reason-box"><strong>Exact risk reasons before approval</strong>{approval.reasons.length ? <ul>{approval.reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul> : <p>No risk reasons supplied by API.</p>}</div><details><summary>Redacted action arguments</summary><pre>{JSON.stringify(approval.action.arguments, null, 2)}</pre></details><div className="approval-footer"><span>Expires {new Date(approval.expires_at).toLocaleString()}</span><div className="button-row"><button disabled={busy} className="button approve" onClick={() => onReview(approval.id, 'approve')}>Approve</button><button disabled={busy} className="button deny" onClick={() => onReview(approval.id, 'deny')}>Deny</button></div></div></article>
}

const simulatorActions: SimulatorAction[] = ['read_public_document', 'read_restricted_document', 'http_get', 'http_post', 'run_shell_command', 'send_email']
const trustLevels: SourceTrustLevel[] = ['trusted', 'untrusted', 'user', 'system', 'unknown']
const defaultArguments = '{\n  "document": "public fixture"\n}'

function CustomActionTest() {
  const [context, setContext] = useState('')
  const [actionType, setActionType] = useState<SimulatorAction>('read_public_document')
  const [toolName, setToolName] = useState('browser')
  const [trust, setTrust] = useState<SourceTrustLevel>('user')
  const [argumentsText, setArgumentsText] = useState(defaultArguments)
  const [result, setResult] = useState<CheckActionResponse | null>(null)
  const [validationError, setValidationError] = useState('')
  const [submitError, setSubmitError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const reset = () => { setContext(''); setActionType('read_public_document'); setToolName('browser'); setTrust('user'); setArgumentsText(defaultArguments); setResult(null); setValidationError(''); setSubmitError('') }
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setValidationError(''); setSubmitError(''); setResult(null)
    let parsed: unknown
    try { parsed = JSON.parse(argumentsText) } catch { setValidationError('Arguments must be valid JSON.'); return }
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') { setValidationError('Arguments must be a JSON object.'); return }
    if (!toolName.trim()) { setValidationError('Tool name is required.'); return }
    setSubmitting(true)
    try {
      const stored = window.localStorage.getItem('agentshield-demo-session')
      let sessionId = stored
      if (!sessionId) { const session = await api.createSession('custom-action-demo'); sessionId = session.id; window.localStorage.setItem('agentshield-demo-session', sessionId) }
      const args = { ...(parsed as Record<string, unknown>), ...(context.trim() ? { user_request_context: context.trim() } : {}) }
      setResult(await api.checkAction({ session_id: sessionId, agent_id: 'custom-action-demo', tool_name: toolName.trim(), action_type: actionType, arguments: args, source_trust_level: trust, simulator_mode: true }))
    } catch (error) { setSubmitError(error instanceof Error ? error.message : 'Unable to evaluate this action.') } finally { setSubmitting(false) }
  }
  const tone = result?.decision === 'block' ? 'red' : result?.decision === 'approval_required' ? 'amber' : 'green'
  return <>
    <SectionHeading eyebrow="Gateway evaluation" title="Custom action test" detail="Submit a user-defined action to the real policy gateway in simulator mode." action={<button className="button ghost" onClick={reset}>↺ Reset form</button>} />
    <div className="custom-warning"><span>⊘</span><div><strong>SIMULATOR MODE · NO REAL EXECUTION</strong><p>This form only calls <code>POST /api/v1/check-action</code>. No tools, network requests, uploads, shell commands, or email are executed.</p></div></div>
    <div className="custom-grid"><form className="panel custom-form" onSubmit={submit}>
      <div className="field"><label htmlFor="custom-context">User request / context</label><textarea id="custom-context" value={context} onChange={(e) => setContext(e.target.value)} placeholder="Describe what the user asked the agent to do…" rows={4} /></div>
      <div className="field-row"><div className="field"><label htmlFor="custom-action">Simulator action</label><select id="custom-action" value={actionType} onChange={(e) => setActionType(e.target.value as SimulatorAction)}>{simulatorActions.map((action) => <option key={action}>{action}</option>)}</select></div><div className="field"><label htmlFor="custom-tool">Tool name <small>(optional)</small></label><input id="custom-tool" value={toolName} onChange={(e) => setToolName(e.target.value)} placeholder="browser" /></div></div>
      <div className="field-row"><div className="field"><label htmlFor="custom-trust">Source trust level</label><select id="custom-trust" value={trust} onChange={(e) => setTrust(e.target.value as SourceTrustLevel)}>{trustLevels.map((level) => <option key={level}>{level}</option>)}</select></div><div className="field"><label>Simulator mode</label><div className="fixed-mode">✓ true · fixed by safety boundary</div></div></div>
      <div className="field"><label htmlFor="custom-args">Action arguments <small>JSON object · document / destination / command / recipient / body / extra arguments</small></label><textarea id="custom-args" className="json-input" value={argumentsText} onChange={(e) => setArgumentsText(e.target.value)} rows={9} spellCheck={false} /></div>
      {validationError && <div className="form-error" role="alert">{validationError}</div>}{submitError && <div className="form-error" role="alert">{submitError}</div>}
      <button className="button safe-action submit-action" type="submit" disabled={submitting}>{submitting ? 'Evaluating…' : 'Evaluate custom action'}</button>
    </form><section className="panel custom-result"><div className="panel-heading"><div><div className="eyebrow">Gateway response</div><h2>Decision evidence</h2></div>{result && <StatusPill tone={tone}>{result.decision}</StatusPill>}</div>{!result && !submitting ? <Empty title="No evaluation yet" detail="Enter an action above to see its policy decision and redacted result." /> : submitting ? <Loading text="Checking action against policy…" /> : result && <div className="result-content"><div className="result-score"><strong>{result.risk_score}</strong><span>risk score / 100</span></div><div className="reason-box"><strong>Reasons</strong>{result.reasons.length ? <ul>{result.reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul> : <p>No reasons returned.</p>}</div>{result.approval_request_id && <div className="evidence-row"><b>Approval ID</b><code>{result.approval_request_id}</code></div>}<div className="evidence-row"><b>Execution</b><span>{result.executed ? 'executed' : 'not executed'} · source {result.source_trust_level}</span></div>{(result.policy_matches?.length || result.detector_findings?.length) ? <div className="reason-box"><strong>Detector / policy evidence</strong>{result.policy_matches?.map((match) => <div key={match}>Policy: {match}</div>)}{result.detector_findings?.map((finding, index) => <div key={`${finding.detector}-${index}`}>Detector: {finding.detector} · {finding.reasons.join(' · ')}</div>)}</div> : null}<details><summary>Redacted / safe result</summary><pre>{JSON.stringify(result.result || { executed: false, note: 'No tool result because this was a check-only request.' }, null, 2)}</pre></details></div>}</section></div>
  </>
}

function AuditForensics() {
  const [sessionId, setSessionId] = useState('')
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [state, setState] = useState<LoadState>('ready')
  const [message, setMessage] = useState('')
  const search = async (event: React.FormEvent) => {
    event.preventDefault(); setMessage(''); setEvents([])
    if (!sessionId.trim()) { setMessage('Enter a session ID to inspect.'); return }
    setState('loading')
    try { const result = await api.audit(sessionId.trim()); setEvents(result.events); setState('ready') }
    catch (error) { setState('error'); setMessage(error instanceof Error ? error.message : 'Unable to load session audit events.') }
  }
  return <><SectionHeading eyebrow="Forensic review" title="Audit forensics" detail="Inspect recorded events for one session. Results reflect the connected API and may be empty." />
    <section className="panel soc-audit-workstation"><form className="soc-audit-search" onSubmit={search}><div className="field"><label htmlFor="audit-session-id">Session ID</label><input id="audit-session-id" value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="sess_…" /></div><button className="button safe-action" type="submit" disabled={state === 'loading'}>{state === 'loading' ? 'Loading…' : 'Load audit events'}</button></form>
    {message && <div className="form-error" role="alert">{message}</div>}{state === 'loading' && <Loading text="Loading session audit events…" />}{state === 'error' && <Empty title="Audit unavailable" detail="The session audit endpoint returned an error. Verify the session ID and API connection." />}{state === 'ready' && sessionId && !message && !events.length && <Empty title="No audit events" detail="The API returned no events for this session." />}{events.length > 0 && <div className="soc-audit-timeline" aria-label="Session audit events">{events.map((item) => <article className="soc-audit-event" key={item.id}><div className="soc-audit-marker" /><div><div className="eyebrow">{formatTime(item.created_at)} · {item.event_type}</div><code>{item.id}</code><pre>{JSON.stringify(item.payload, null, 2)}</pre></div></article>)}</div>}</section></>
}

type CockpitProps = {
  trace: DemoTrace | null
  approvals: Approval[]
  approvalsState: LoadState
  health: LoadState
  onRun: (scenario: 'safe' | 'attack') => void
  onNavigate: (view: View) => void
}

function redactPayload(value: unknown): unknown {
  if (typeof value === 'string') return value.replace(/\b(?:sk-[\w-]{12,}|AKIA[A-Z0-9]{16}|Bearer\s+[^\s]+)\b/g, '[REDACTED]').replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED EMAIL]')
  if (Array.isArray(value)) return value.map(redactPayload)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => {
    const sensitive = /token|secret|password|api.?key|authorization|credential|cookie/i.test(key)
    return [key, sensitive ? '[REDACTED]' : redactPayload(item)]
  }))
}

function riskFactorsFor(event: TraceEvent): Array<{ label: string; value: number }> {
  const candidate = (event as TraceEvent & { risk_factors?: unknown }).risk_factors
  if (Array.isArray(candidate)) return candidate.filter((item) => item && typeof item === 'object').map((item) => {
    const factor = item as { name?: string; label?: string; score?: number; value?: number; weight?: number }
    return { label: (factor.label || factor.name || 'Risk factor').replace(/_/g, ' '), value: Number(factor.weight ?? factor.value ?? factor.score ?? 0) || 0 }
  })
  if (candidate && typeof candidate === 'object') return Object.entries(candidate as Record<string, unknown>).map(([label, value]) => ({ label: label.replace(/_/g, ' '), value: Math.max(0, Math.min(100, Number(value) || 0)) }))
  return []
}

function InterceptCard({ event, selected, onSelect }: { event: TraceEvent; selected: boolean; onSelect: () => void }) {
  const tone = event.decision === 'block' ? 'red' : event.risk_score >= 40 ? 'amber' : 'green'
  const tool = event.tool_call?.tool_name || 'policy-engine'
  const agent = (event as TraceEvent & { agent_id?: string }).agent_id || 'Not supplied'
  const findings = event.detector_findings.filter((finding) => finding.detected)
  return <button className={`intercept-card ${selected ? 'selected' : ''}`} onClick={onSelect} aria-pressed={selected}>
    <div className="intercept-card-top"><span className="intercept-sequence">{String(event.sequence).padStart(2, '0')}</span><StatusPill tone={tone}>{event.decision}</StatusPill><time>{event.event_type.replace(/_/g, ' ')}</time></div>
    <div className="intercept-card-title"><strong>{event.description}</strong><span className="intercept-chevron">›</span></div>
    <div className="intercept-meta"><span>Agent: {agent}</span><span>Tool: {tool}</span><span>Risk {event.risk_score}/100</span></div>
    <pre className="intercept-payload">{JSON.stringify(redactPayload(event.tool_call?.arguments || {}), null, 2)}</pre>
    <div className="intercept-evidence">{findings.length ? findings.map((finding) => <span key={finding.detector}>● {finding.detector.replace(/_/g, ' ')}</span>) : event.policy_matches.length ? <span>● {event.policy_matches[0]}</span> : <span>● No detector findings</span>}</div>
  </button>
}

function CockpitInspector({ event, onNavigate }: { event: TraceEvent | null; onNavigate: (view: View) => void }) {
  if (!event) return <aside className="forensics-inspector"><div className="inspector-empty"><span className="inspector-crosshair">⌁</span><h2>Deep forensics inspector</h2><p>Run a scenario to populate live intercept evidence.</p></div></aside>
  const factors = riskFactorsFor(event)
  const payload = event.tool_call ? redactPayload(event.tool_call.arguments) : { event_type: event.event_type }
  return <aside className="forensics-inspector"><div className="inspector-heading"><div><span className="eyebrow">Selected event</span><h2>Deep forensics</h2></div><StatusPill tone={event.decision === 'block' ? 'red' : event.risk_score >= 40 ? 'amber' : 'green'}>{event.decision}</StatusPill></div>
    <div className="inspector-event"><span className="inspector-event-id">{event.event_id}</span><h3>{event.description}</h3><p>{event.event_type.replace(/_/g, ' ')} · sequence {event.sequence}</p></div>
    <div className="inspector-section"><div className="inspector-section-title"><span>Risk score</span><strong>{event.risk_score}/100</strong></div>{factors.length ? factors.map((factor) => <div className="risk-factor" key={factor.label}><div><span>{factor.label}</span><b>{factor.value}</b></div><div className="risk-track"><i style={{ width: `${Math.max(0, Math.min(100, Math.abs(factor.value)))}%` }} /></div></div>) : <p className="muted">No risk-factor breakdown returned by the API.</p>}</div>
    <div className="inspector-section"><h4>Reasons &amp; policy matches</h4>{event.reasons.length || event.policy_matches.length ? <ul className="inspector-list">{event.reasons.map((reason, index) => <li key={`reason-${index}`}>{reason}</li>)}{event.policy_matches.map((policy) => <li key={policy}><b>Policy:</b> {policy}</li>)}</ul> : <p className="muted">No reasons or policy matches returned.</p>}</div>
    <div className="inspector-section"><h4>Sanitized payload</h4><pre className="sanitized-payload">{JSON.stringify(payload, null, 2)}</pre></div>
    {event.detector_findings.some((finding) => finding.detected) && <div className="inspector-section"><h4>Detector findings</h4>{event.detector_findings.filter((finding) => finding.detected).map((finding, index) => <FindingPreview key={`${finding.detector}-${index}`} finding={finding} />)}</div>}
    <div className="inspector-safe-meta"><span>Execution: <b>{event.tool_call?.executed ? 'reported executed' : 'not executed'}</b></span><span>Source: <b>{event.event_type === 'approval_request' ? 'Approval API' : 'Demo trace'}</b></span></div>
    <div className="inspector-actions"><button className="button ghost" onClick={() => onNavigate('audit')}>View audit</button><button className="button ghost" onClick={() => onNavigate('activity')}>Open activity</button></div>
  </aside>
}

function OverviewCockpit({ trace, approvals, approvalsState, health, onRun, onNavigate }: CockpitProps) {
  const traceEvents = trace?.events.filter((event) => event.event_type !== 'scenario_started') || []
  const approvalEvents: TraceEvent[] = approvals.filter((approval) => approval.status === 'pending').map((approval, index) => ({
    sequence: index + 1, event_id: approval.id, event_type: 'approval_request', description: `Approval requested: ${approval.action.action_type}`, risk_score: approval.risk_score,
    decision: 'approval_required', tool_call: { tool_name: approval.action.tool_name, action_type: approval.action.action_type, arguments: approval.action.arguments, executed: false },
    detector_findings: [], reasons: approval.reasons, policy_matches: Array.isArray(approval.policy_context.policy_matches) ? approval.policy_context.policy_matches.filter((match): match is string => typeof match === 'string') : [],
    ...{ agent_id: approval.action.agent_id },
  }))
  const events = [...traceEvents, ...approvalEvents]
  const [filter, setFilter] = useState<'all' | 'blocked' | 'approval_required' | 'allow'>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = events.find((event) => event.event_id === selectedId) || events.slice().reverse().sort((a, b) => b.risk_score - a.risk_score)[0] || null
  const visible = filter === 'all' ? events : events.filter((event) => event.decision === (filter === 'blocked' ? 'block' : filter))
  const blocked = events.filter((event) => event.decision === 'block').length
  const approvalsPending = approvals.filter((approval) => approval.status === 'pending').length
  const findings = events.reduce((sum, event) => sum + event.detector_findings.filter((finding) => finding.detected).length, 0)
  const avgRisk = events.length ? Math.round(events.reduce((sum, event) => sum + event.risk_score, 0) / events.length) : null
  const metricSource = trace ? 'Demo trace + approval API' : approvalEvents.length ? 'Approval API' : 'No telemetry'
  return <div className="security-cockpit"><div className="cockpit-heading"><div><span className="eyebrow">Runtime telemetry</span><h1>Security operations cockpit</h1><p>Trace-backed interception and deterministic policy evidence.</p></div><div className="cockpit-health"><span className={health === 'ready' ? 'online-dot' : 'offline-dot'} />{health === 'ready' ? 'Gateway online' : health === 'loading' ? 'Connecting…' : 'No telemetry'}</div></div>
    <div className="runtime-kpis"><Metric icon="◉" tone="blue" value={events.length || trace ? events.length : '—'} label="Events observed" source={metricSource} /><Metric icon="⌁" tone="red" value={trace ? blocked : '—'} label="Blocked" source={metricSource} /><Metric icon="◷" tone="amber" value={approvalsState === 'ready' ? approvalsPending : '—'} label="Pending approvals" source={approvalsState === 'ready' ? 'Live approval API' : 'No telemetry'} /><Metric icon="!" tone="red" value={trace ? findings : '—'} label="Findings" source={metricSource} /><Metric icon="◇" tone="blue" value={avgRisk === null ? '—' : avgRisk} label="Average risk" source={metricSource} /></div>
    <div className="stream-toolbar"><div><span className="eyebrow">Firewall event stream</span><h2>Live intercepts</h2></div><div className="stream-filters" role="group" aria-label="Stream filters">{(['all', 'blocked', 'approval_required', 'allow'] as const).map((item) => <button key={item} className={filter === item ? 'active' : ''} onClick={() => setFilter(item)}>{item === 'all' ? 'All events' : item.replace(/_/g, ' ')}</button>)}</div></div>
    <div className="cockpit-grid"><section className="intercept-stream"><div className="stream-status"><span className="live-indicator" />{trace ? `${visible.length} trace events · ${trace.scenario} scenario` : 'No telemetry loaded'}<span className="stream-note">{trace ? 'Redacted evidence only' : 'Run a simulator to begin'}</span></div>{visible.length ? visible.slice().reverse().map((event) => <InterceptCard key={event.event_id} event={event} selected={selected?.event_id === event.event_id} onSelect={() => setSelectedId(event.event_id)} />) : <Empty title="No intercept events" detail="Run the deterministic attack or safe scenario to populate this stream." />}</section><div className="cockpit-right-pane">
    <div className="replay-cta"><div><span className="eyebrow">Deterministic replay</span><h2>Reproduce an attack trace safely</h2><p>Run the backend simulator to inspect policy decisions. No external tools or destinations are contacted.</p></div><div className="replay-actions"><button className="button attack-action" onClick={() => onRun('attack')}>⚠ Run Attack Scenario</button><button className="button safe-action" onClick={() => onRun('safe')}>▶ Run Safe Scenario</button></div></div>
    <CockpitInspector event={selected} onNavigate={onNavigate} /></div></div>
    <section className="audit-stream-strip"><div><span className="eyebrow">Audit stream</span><h2>Latest recorded evidence</h2></div><div className="audit-strip-events">{events.slice().reverse().slice(0, 3).map((event) => <button key={event.event_id} onClick={() => setSelectedId(event.event_id)}><span>{event.event_type.replace(/_/g, ' ')}</span><b>{event.decision}</b><small>{event.event_id}</small></button>)}{!events.length && <span className="muted">No audit events in the current trace.</span>}</div><button className="button ghost" onClick={() => onNavigate('audit')}>Open audit</button></section>
  </div>
}

function App() {
  const [view, setView] = useState<View>('cockpit'); const [health, setHealth] = useState<LoadState>('loading'); const [approvalsState, setApprovalsState] = useState<LoadState>('loading'); const [approvals, setApprovals] = useState<Approval[]>([]); const [error, setError] = useState(''); const [trace, setTrace] = useState<DemoTrace | null>(null); const [traceState, setTraceState] = useState<LoadState>('ready'); const [visibleCount, setVisibleCount] = useState(0); const [reviewing, setReviewing] = useState(''); const [now, setNow] = useState(new Date()); const timerRef = useRef<number | undefined>(undefined)
  const clearPlayback = useCallback(() => { if (timerRef.current !== undefined) window.clearInterval(timerRef.current); timerRef.current = undefined }, [])
  useEffect(() => () => clearPlayback(), [clearPlayback])
  const loadApprovals = useCallback(async () => { setApprovalsState('loading'); try { const result = await api.approvals(); setApprovals(result.approvals); setApprovalsState('ready'); setError('') } catch { setApprovalsState('error'); setError('Unable to load approval data from the AgentShield API.') } }, [])
  useEffect(() => { api.health().then(() => setHealth('ready')).catch(() => setHealth('error')); loadApprovals(); const timer = window.setInterval(() => setNow(new Date()), 60000); return () => window.clearInterval(timer) }, [loadApprovals])
  const runScenario = async (scenario: 'safe' | 'attack') => { clearPlayback(); setTrace(null); setVisibleCount(0); setTraceState('loading'); setView('trace'); setError(''); try { const result = scenario === 'safe' ? await api.runSafe() : await api.runAttack(); setTrace(result); setTraceState('ready'); let count = 0; timerRef.current = window.setInterval(() => { count += 1; setVisibleCount(count); if (count >= result.events.length) clearPlayback() }, 650) } catch { setTraceState('error'); setError('Unable to run the deterministic simulator. Check that the backend is available.') } }
  const resetDemo = () => { clearPlayback(); setTrace(null); setVisibleCount(0); setTraceState('ready'); setError('') }
  const review = async (id: string, decision: 'approve' | 'deny') => { setReviewing(id); try { await api.reviewApproval(id, decision); await loadApprovals() } catch { setError(`Unable to ${decision} this approval. Please try again.`) } finally { setReviewing('') } }
  const pending = useMemo(() => approvals.filter((item) => item.status === 'pending'), [approvals]); const shownEvents = trace?.events.slice(0, visibleCount) || []; const activity = shownEvents.filter((event) => event.event_type !== 'scenario_started'); const toolEvents = shownEvents.filter((event) => event.event_type === 'tool_call'); const blockedCount = shownEvents.filter((event) => event.decision === 'block').length; const allowedCount = shownEvents.filter((event) => event.decision === 'allow').length; const injectionCount = shownEvents.reduce((total, event) => total + event.detector_findings.filter((f) => f.detector === 'prompt_injection' && f.detected).length, 0); const sensitiveCount = shownEvents.reduce((total, event) => total + event.detector_findings.filter((f) => f.detector === 'sensitive_data' && f.detected).length, 0); const averageRisk = toolEvents.length ? Math.round(toolEvents.reduce((total, event) => total + event.risk_score, 0) / toolEvents.length) : null; const metricLabel = trace ? 'Simulator trace · live playback' : 'Run simulator to populate'; const demoAction = <div className="demo-actions"><button className="button safe-action" onClick={() => runScenario('safe')}>▶ Run Safe Scenario</button><button className="button attack-action" onClick={() => runScenario('attack')}>⚠ Run Attack Scenario</button>{trace && <button className="button ghost" onClick={resetDemo}>↺ Reset Demo</button>}</div>

  return <div className="app-shell soc-dashboard"><aside className="sidebar soc-sidebar"><div className="brand"><div className="brand-mark">A<span>+</span></div><div><strong>AgentShield</strong><small>SECURITY CONTROL</small></div></div><div className="sidebar-label">Workspace</div><nav aria-label="Security workspace">{nav.map((item) => <button key={item.id} className={view === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setView(item.id)}><span>{item.icon}</span>{item.label}{item.id === 'approvals' && pending.length > 0 && <b>{pending.length}</b>}</button>)}</nav><div className="sidebar-bottom"><div className="connection"><span className={health === 'ready' ? 'online-dot' : 'offline-dot'} /><div><strong>{health === 'ready' ? 'API connected' : health === 'loading' ? 'Connecting…' : 'API unavailable'}</strong><small>{api.baseUrl}</small></div></div><div className="user-chip"><div className="avatar">DR</div><div><strong>Demo reviewer</strong><small>Security operator</small></div></div></div></aside><main className="main soc-main"><header className="topbar"><div className="mobile-brand"><div className="brand-mark">A<span>+</span></div><strong>AgentShield</strong></div><div className="breadcrumb"><span>Workspace</span><b>/</b><strong>{nav.find((item) => item.id === view)?.label}</strong></div><div className="top-actions"><span className="last-sync">Last sync {now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span><button className="avatar" aria-label="Demo reviewer">DR</button></div></header><div className="content soc-content">{error && <div className="alert" role="alert"><span>!</span>{error}<button onClick={() => setError('')}>×</button></div>}
    {view === 'overview' && <><SectionHeading eyebrow="Deterministic demo" title="Security control center" detail="A presentation-ready local simulator for safe and adversarial agent behavior." action={demoAction} /><div className="simulator-strip"><span className="simulator-pulse" /><div><strong>LOCAL SIMULATOR · NO EXTERNAL CONTACT</strong><p>Every scenario uses fixed backend fixtures. Tool calls are evaluated and recorded, never executed.</p></div></div><div className="hero-status"><div className="shield">{health === 'ready' ? '✓' : '!'}</div><div><div className="eyebrow">Protection status</div><h2>Gateway connection status</h2><p>The dashboard reports API reachability and simulator evidence; it does not imply live protection when disconnected.</p></div><StatusPill tone={health === 'ready' ? 'blue' : 'amber'}>{health === 'ready' ? 'Connected' : 'Disconnected'}</StatusPill></div><div className="metric-note">Metrics count tool-call events in the latest simulator trace and pending approvals returned by the API. No synthetic production activity is shown. LOCAL DEMO.</div><div className="stat-grid"><Metric icon="◉" tone="blue" value={trace ? toolEvents.length : '—'} label="Actions inspected" source={metricLabel} /><Metric icon="↗" tone="green" value={trace ? allowedCount : '—'} label="Allowed actions" source={metricLabel} /><Metric icon="⌁" tone="red" value={trace ? blockedCount : '—'} label="Blocked actions" source={metricLabel} /><Metric icon="◷" tone="amber" value={pending.length} label="Pending approvals" source="Live API data" /><Metric icon="!" tone="red" value={trace ? injectionCount : '—'} label="Prompt-injection attempts" source={metricLabel} /><Metric icon="◇" tone="amber" value={trace ? sensitiveCount : '—'} label="Sensitive-data incidents" source={metricLabel} /><Metric icon="◎" tone="blue" value={averageRisk === null ? '—' : averageRisk} label="Average risk score" source={metricLabel} /></div><div className="overview-grid"><section className="panel"><div className="panel-heading"><div><div className="eyebrow">Recent signal</div><h2>Live activity</h2></div><button className="text-button" onClick={() => setView('activity')}>View all →</button></div>{activity.length ? activity.slice(-4).reverse().map((event) => <ActivityRow event={event} key={event.event_id} />) : <Empty title="No activity loaded" detail="Run a scenario to see the redacted event stream." />}</section><section className="panel"><div className="panel-heading"><div><div className="eyebrow">Human-in-the-loop</div><h2>Approval queue</h2></div><button className="text-button" onClick={() => setView('approvals')}>Open queue →</button></div>{pending.length ? pending.slice(0, 3).map((approval) => <div className="mini-approval" key={approval.id}><span className="tool-icon">⌘</span><div><strong>{approval.action.tool_name}</strong><small>Risk {approval.risk_score} · {approval.reasons[0] || 'Review required'}</small></div><StatusPill tone="amber">Pending</StatusPill></div>) : <Empty title="Queue is clear" detail="No pending approval requests were returned by the API." />}</section></div></>}
     <div className="mobile-navigation field"><label htmlFor="mobile-view">Workspace navigation</label><select id="mobile-view" value={view} onChange={e => setView(e.target.value as View)}>{nav.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</select></div>
      {view === 'cockpit' && <OverviewCockpit trace={trace} approvals={approvals} approvalsState={approvalsState} health={health} onRun={runScenario} onNavigate={setView} />}
      <ApiAccess />
      {view === 'agents' && <Agents />}
      {view === 'monitor-chat' && <MonitorChat />}
      {view === 'audit' && <AuditForensics />}
     {view === 'custom-action' && <CustomActionTest />}
     {view === 'activity' && <><SectionHeading eyebrow="Observability" title="Live activity" detail="Chronological events returned by the latest simulator trace." action={demoAction} /><section className="panel activity-panel">{activity.length ? activity.slice().reverse().map((event) => <ActivityRow event={event} expanded key={event.event_id} />) : <Empty title="No live activity yet" detail="Start a scenario to inspect real backend trace events." />}</section></>}
    {view === 'trace' && <><SectionHeading eyebrow="Investigation" title={trace?.scenario === 'safe' ? 'Safe scenario playback' : 'Attack scenario playback'} detail="Watch each deterministic event arrive, then inspect the enforcement evidence." action={demoAction} />{traceState === 'loading' ? <Loading text="Requesting deterministic simulator trace…" /> : traceState === 'error' ? <Empty title="Trace unavailable" detail="The simulator could not be reached. Check the API connection and try again." /> : trace ? <><div className={`trace-banner ${trace.final_decision === 'allow' ? 'safe-banner' : ''}`}><div><StatusPill tone={trace.final_decision === 'block' ? 'red' : 'green'}>{trace.final_decision === 'block' ? 'BLOCKED' : 'ALLOWED'}</StatusPill><h2>{trace.final_decision === 'block' ? 'Attack contained by policy' : 'Safe research allowed'}</h2><p>{trace.explanation}</p></div><span className="demo-label">LOCAL DEMO<br /><small>Simulator mode · no external contact</small></span></div>{trace.final_decision === 'block' && <div className="contact-proof"><span>⊘</span><div><strong>Proof: attacker destination was not contacted</strong><p>Simulator mode evaluated the counterfactual upload only. <b>executed: false</b> — no network request or external destination contact occurred.</p></div></div>}<Playback trace={trace} visibleCount={visibleCount} /></> : <Empty title="No scenario loaded" detail="Choose Run Safe Scenario or Run Attack Scenario to start playback." />}</>}
    {view === 'approvals' && <><SectionHeading eyebrow="Human review" title="Approval queue" detail="Review high-risk actions before they reach execution." action={<button className="button ghost" onClick={loadApprovals}>↻ Refresh</button>} />{approvalsState === 'loading' ? <Loading text="Loading approval requests…" /> : approvalsState === 'error' ? <Empty title="Approval queue unavailable" detail="The API did not return approval data. Check the backend connection and retry." /> : pending.length ? <div className="approval-list">{pending.map((approval) => <ApprovalCard key={approval.id} approval={approval} onReview={review} busy={reviewing === approval.id} />)}</div> : <Empty title="No actions need review" detail="The live approval endpoint returned an empty queue." />}</>}
    {view === 'policy' && <><SectionHeading eyebrow="Governance" title="Policy catalog" detail="Configured default protections explained for operators." /><div className="catalog-note"><span>i</span><p>This is a static policy catalog for the configured default policy engine. It is explanatory and is not fetched from a policy endpoint.</p></div><div className="policy-grid">{policyCatalog.map(([title, detail], index) => <article className="policy-card" key={title}><div className="policy-number">0{index + 1}</div><StatusPill tone="blue">Configured</StatusPill><h2>{title}</h2><p>{detail}</p><div className="policy-rule">Default enforcement rule <span>→</span></div></article>)}</div></>}
  </div></main></div>
}

export default App
