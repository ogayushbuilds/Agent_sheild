import { request, type AuditEvent, type DetectorFinding } from './api'

export type AgentEnvironment = 'development' | 'staging' | 'production'
export type AgentCreate = { name: string; external_agent_id: string; environment: AgentEnvironment; description: string; allowed_tools: string[]; approved_domains: string[] }
export type Agent = AgentCreate & { id: string; status: 'active' | 'paused' | 'disabled'; created_at: string; updated_at: string }
export type AgentMetrics = { actions: number; incidents: number; blocked: number; approval_required: number; allowed: number; prompt_injection_incidents: number; sensitive_data_incidents: number; average_risk_score: number; pending_approvals: number; last_activity_timestamp: string | null }
export type AgentDetail = Agent & { metrics: AgentMetrics }
export type AgentAction = { id: string; agent_id: string; session_id: string; tool_name: string; action_type: string; decision: string; risk_score: number; reasons: string[]; arguments: Record<string, unknown>; timestamp: string; prompt_injection: Record<string, unknown> | null; sensitive_data: Record<string, unknown> | null; matched_policies: string[] }
export type AgentIncident = { id: string; agent_id: string; session_id: string; action_request_id: string; severity: string; decision: string; reasons: string[]; created_at: string }
export type ChatSource = 'pasted_text' | 'metadata_only' | 'chatgpt_share'
export type ChatSession = { id: string; source_type: ChatSource; url: string | null; metadata: Record<string, unknown>; status: 'created' | 'evaluated' | 'not_evaluated' | 'analysis_failed'; created_at: string }
export type ChatCreate = { source_type: ChatSource; url?: string; metadata: Record<string, unknown> }
export type ChatAnalysis = { session: ChatSession; status: 'evaluated' | 'not_evaluated'; limitation: string | null; findings: DetectorFinding[]; urls_detected: string[]; tool_call_instructions_detected: boolean; redacted_preview: string; risk_score: number | null; source_trust_level: 'untrusted'; executed: false; decision?: string; policy_matches?: string[]; reasons?: string[] }
export type ChatEvent = AuditEvent & { sequence: number; redacted_text: string | null }
const post = (value: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(value) })
const agentPath = (id: string) => `/api/v1/agents/${encodeURIComponent(id)}`
const chatPath = (id: string) => `/api/v1/chat-monitor/sessions/${encodeURIComponent(id)}`
export const monitorApi = {
  agents: () => request<{ agents: Agent[] }>('/api/v1/agents'),
  createAgent: (value: AgentCreate) => request<Agent>('/api/v1/agents', post(value)),
  agent: (id: string) => request<AgentDetail>(agentPath(id)),
  status: (id: string, action: 'pause' | 'resume') => request<Agent>(`${agentPath(id)}/${action}`, post({})),
  actions: (id: string) => request<{ actions: AgentAction[] }>(`${agentPath(id)}/actions`),
  incidents: (id: string) => request<{ incidents: AgentIncident[] }>(`${agentPath(id)}/incidents`),
  audit: (id: string) => request<{ events: AuditEvent[] }>(`${agentPath(id)}/audit-events`),
  createChat: (value: ChatCreate) => request<ChatSession>('/api/v1/chat-monitor/sessions', post(value)),
   analyzeChat: (id: string, pasted_text?: string, fetch_consent = false) => request<ChatAnalysis>(`${chatPath(id)}/analyze`, post({ ...(pasted_text === undefined ? {} : { pasted_text }), ...(fetch_consent ? { fetch_consent: true } : {}) })),
  chatEvents: (id: string) => request<{ events: ChatEvent[] }>(`${chatPath(id)}/events`),
  chatAudit: (id: string) => request<{ events: AuditEvent[] }>(`${chatPath(id)}/audit-events`),
}
