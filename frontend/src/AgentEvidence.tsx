import { type AgentAction, type AgentMetrics } from './monitorApi'

const metricLabels: [keyof Omit<AgentMetrics, 'last_activity_timestamp'>, string][] = [
  ['actions', 'Actions inspected'], ['allowed', 'Allowed actions'], ['blocked', 'Blocked actions'],
  ['incidents', 'Incidents'], ['approval_required', 'Approval-required actions'],
  ['prompt_injection_incidents', 'Prompt-injection incidents'], ['sensitive_data_incidents', 'Sensitive-data incidents'],
  ['average_risk_score', 'Average risk score'], ['pending_approvals', 'Pending approvals'],
]
export function AgentSummary({ metrics }: { metrics: AgentMetrics }) {
  return <><div className="stat-grid">{metricLabels.map(([key, label]) => <div className="stat-card" key={key}><div><strong>{key === 'average_risk_score' ? Number(metrics[key].toFixed(2)) : metrics[key]}</strong><small>{label}</small><em>Recorded API data</em></div></div>)}</div><p>Last activity: {metrics.last_activity_timestamp ? new Date(metrics.last_activity_timestamp).toLocaleString() : 'No recorded activity'}</p><p>Detector incident counts reflect stored evidence only; historical actions without evidence cannot establish whether a detector matched.</p></>
}
function Finding({ label, value }: { label: string; value: Record<string, unknown> | null }) {
  return <div className="reason-box"><strong>{label}</strong>{value === null ? <p>Historical detector evidence unavailable; detection status is unknown.</p> : <><p>Detection status: {value.detected === true ? 'Detected' : value.detected === false ? 'Not detected' : 'Not supplied'}</p><details><summary>Stored {label.toLowerCase()} finding</summary><pre>{JSON.stringify(value, null, 2)}</pre></details></>}</div>
}
export function AgentActionEvidence({ action }: { action: AgentAction }) {
  return <article><h3>{action.tool_name} / {action.action_type}</h3><p>{action.decision} · Risk {action.risk_score} · Session {action.session_id}</p><p>Recorded {new Date(action.timestamp).toLocaleString()}</p><p>{action.reasons.join(' · ')}</p><Finding label="Prompt injection" value={action.prompt_injection} /><Finding label="Sensitive data" value={action.sensitive_data} /><div className="reason-box"><strong>Matched policies</strong>{action.matched_policies.length ? <ul>{action.matched_policies.map((policy, i) => <li key={i}>{policy}</li>)}</ul> : <p>No stored matched policies returned.</p>}</div><details><summary>Action arguments</summary><pre>{JSON.stringify(action.arguments, null, 2)}</pre></details></article>
}
