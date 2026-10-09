export type Health = { status?: string; service?: string }
export type Session = { id: string; agent_id: string; metadata: Record<string, unknown>; created_at: string }
export type SimulatorAction = 'read_public_document' | 'read_restricted_document' | 'http_get' | 'http_post' | 'run_shell_command' | 'send_email'
export type SourceTrustLevel = 'trusted' | 'untrusted' | 'user' | 'system' | 'unknown'
export type CheckActionRequest = { session_id: string; agent_id: string; tool_name: string; action_type: SimulatorAction; arguments: Record<string, unknown>; source_trust_level: SourceTrustLevel; simulator_mode: true }
export type CheckActionResponse = { action_request_id: string; decision: 'allow' | 'block' | 'approval_required' | 'redact'; risk_score: number; reasons: string[]; source_trust_level: string; executed: boolean; result?: Record<string, unknown> | null; approval_request_id?: string | null; detector_findings?: DetectorFinding[]; policy_matches?: string[]; policy_context?: Record<string, unknown> }

export type Approval = {
  id: string
  action_request_id: string
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'consumed'
  risk_score: number
  reasons: string[]
  policy_context: Record<string, unknown>
  expires_at: string
  created_at: string
  acted_at?: string | null
  reviewer?: string | null
  action: {
    session_id?: string
    agent_id?: string
    tool_name: string
    action_type: string
    arguments: Record<string, unknown>
    source_trust_level?: string
  }
}

export type AuditEvent = { id: string; session_id: string; event_type: string; payload: Record<string, unknown>; created_at: string }
export type DetectorFinding = { detector: string; detected: boolean; indicators: string[]; categories: string[]; severity: string; confidence: number; redacted_preview: string; reasons: string[] }
export type TraceEvent = {
  sequence: number; event_id: string; event_type: string; description: string; risk_score: number
  decision: 'allow' | 'block' | 'approval_required' | 'observed'; tool_call?: { tool_name: string; action_type: string; arguments: Record<string, unknown>; executed: boolean }
  detector_findings: DetectorFinding[]; policy_matches: string[]; reasons: string[]
}
export type DemoTrace = { trace_id: string; scenario: 'safe' | 'attack'; simulator_mode: true; final_decision: 'allow' | 'block'; explanation: string; events: TraceEvent[] }

const baseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '')
let apiKey = ''
export function setApiKey(value: string) { apiKey = value.trim() }

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(apiKey ? { 'x-agentshield-api-key': apiKey } : {}), ...(init?.headers || {}) } })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(detail || `API returned ${response.status}`)
  }
  return response.json() as Promise<T>
}

export const api = {
  baseUrl,
  health: () => request<Health>('/health'),
  approvals: () => request<{ approvals: Approval[] }>('/api/v1/approvals'),
  reviewApproval: (id: string, decision: 'approve' | 'deny') => request<Approval>(`/api/v1/approvals/${id}/${decision}`, { method: 'POST', body: JSON.stringify({ reviewer: 'dashboard-reviewer' }) }),
  runAttack: () => request<DemoTrace>('/api/v1/demo/attack-run', { method: 'POST', body: JSON.stringify({}) }),
  runSafe: () => request<DemoTrace>('/api/v1/demo/safe-run', { method: 'POST', body: JSON.stringify({}) }),
  trace: (id: string) => request<DemoTrace>(`/api/v1/demo/trace/${encodeURIComponent(id)}`),
  audit: (sessionId: string) => request<{ events: AuditEvent[] }>(`/sessions/${encodeURIComponent(sessionId)}/audit-events`),
  createSession: (agent_id: string) => request<Session>('/sessions', { method: 'POST', body: JSON.stringify({ agent_id, metadata: { simulator: true, source: 'custom-action-test' } }) }),
  checkAction: (payload: CheckActionRequest) => request<CheckActionResponse>('/api/v1/check-action', { method: 'POST', body: JSON.stringify(payload) }),
}
