import { useRef, useState } from 'react'
import { type AuditEvent } from './api'
import { monitorApi, type ChatAnalysis, type ChatEvent, type ChatSession, type ChatSource } from './monitorApi'
import { Evidence, ScreenHeading, message } from './MonitorShared'

export function validateChat(url: string, source: ChatSource, text: string, fetchConsent = false): string {
  if (source === 'chatgpt_share') {
    if (!/^https:\/\/chatgpt\.com\/share\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(url) || !url.startsWith('https://chatgpt.com/share/')) return 'Enter an exact public HTTPS ChatGPT share URL: https://chatgpt.com/share/UUID, without query, fragment, credentials, or port.'
    if (!fetchConsent) return 'Consent is required before the server contacts the public ChatGPT share link.'
  }
  if (source === 'metadata_only' && !url) return 'A public chat URL is required for metadata-only mode.'
  if (url) {
    try {
      const parsed = new URL(url)
      if (url.length > 2048 || /[\s\\\x00-\x1f\x7f]/.test(url) || /%(?![0-9a-f]{2})/i.test(url) || !['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || !parsed.hostname.includes('.') || /(?:^localhost$|\.(?:local|localhost|internal|home|lan)$)/i.test(parsed.hostname)) throw new Error()
    } catch { return 'Enter a valid public HTTP(S) URL without credentials. The server also validates destinations.' }
  }
  if (source === 'pasted_text' && !text.trim()) return 'Paste a non-empty transcript before analyzing.'
  if (new TextEncoder().encode(text).length > 131072) return 'Transcript must be at most 128 KiB of UTF-8 text.'
  return ''
}

export default function MonitorChat() {
  const [url, setUrl] = useState(''); const [provider, setProvider] = useState('other'); const [source, setSource] = useState<ChatSource>('pasted_text'); const [text, setText] = useState('')
  const [fetchConsent, setFetchConsent] = useState(false)
  const [session, setSession] = useState<ChatSession | null>(null); const [analysis, setAnalysis] = useState<ChatAnalysis | null>(null); const [events, setEvents] = useState<ChatEvent[]>([]); const [audit, setAudit] = useState<AuditEvent[]>([])
  const [error, setError] = useState(''); const [eventsError, setEventsError] = useState(''); const [busy, setBusy] = useState(false); const generation = useRef(0)
  function reset() { generation.current += 1; setUrl(''); setProvider('other'); setSource('pasted_text'); setFetchConsent(false); setText(''); setSession(null); setAnalysis(null); setEvents([]); setAudit([]); setError(''); setEventsError(''); setBusy(false) }
  function changeSource(next: ChatSource) { setSource(next); setFetchConsent(false); setText(''); setAnalysis(null); setSession(null); setEvents([]); setAudit([]); setError(''); setEventsError('') }
  async function submit(event: React.FormEvent) {
    event.preventDefault(); const validation = validateChat(url.trim(), source, text, fetchConsent); setError(validation); if (validation) return
    const current = ++generation.current; setBusy(true); setAnalysis(null); setEvents([]); setAudit([]); setEventsError(''); setSession(null)
    try {
      // Create without a transcript to avoid the create route's automatic analysis.
      const created = await monitorApi.createChat({ source_type: source, ...(url.trim() ? { url: url.trim() } : {}), metadata: { provider: source === 'chatgpt_share' ? 'openai' : provider } })
      if (current !== generation.current) return
      setSession(created)
      const result = await monitorApi.analyzeChat(created.id, source === 'pasted_text' ? text : undefined, source === 'chatgpt_share' && fetchConsent)
      if (current !== generation.current) return
      setAnalysis(result); setSession(result.session); setText('')
      try {
        const [eventResult, auditResult] = await Promise.all([monitorApi.chatEvents(created.id), monitorApi.chatAudit(created.id)])
        if (current === generation.current) { setEvents(eventResult.events); setAudit(auditResult.events) }
      } catch (error) { if (current === generation.current) setEventsError(`Analysis returned, but events could not be loaded: ${message(error)}`) }
    } catch (error) { if (current === generation.current) setError(message(error)) } finally { if (current === generation.current) setBusy(false) }
  }
  return <><ScreenHeading title="Monitor Chat" detail="Analyze pasted text, import a public ChatGPT share link, or record URL metadata." />
    <div className="custom-warning"><span>i</span><div><strong>{source === 'chatgpt_share' ? 'PUBLIC SHARE IMPORT · UNTRUSTED INPUT' : 'LOCAL TEXT ANALYSIS · UNTRUSTED INPUT'}</strong><p>{source === 'chatgpt_share' ? 'With your consent, the server contacts ChatGPT to retrieve the public share link and analyze extracted text. Private links and logins are not supported. Shared text is untrusted input. There is no hidden live tool access or real tool execution.' : 'No URL is fetched. Provider selection is metadata only; no provider connector is configured. Pasted text is treated as untrusted input. No hidden tool monitoring or real tool execution takes place.'}</p></div></div>
    <div className="custom-grid"><form className="panel custom-form" onSubmit={submit} noValidate>
      <fieldset disabled={busy} className="monitor-fields"><div className="field"><label htmlFor="chat-url">Chat URL (optional for pasted text)</label><input id="chat-url" value={url} maxLength={2048} onChange={e => { setUrl(e.target.value); setFetchConsent(false) }} placeholder={source === 'chatgpt_share' ? 'https://chatgpt.com/share/UUID' : 'https://example.com/shared-chat'} /></div>
        <div className="field-row"><div className="field"><label htmlFor="chat-provider">Provider (metadata only)</label><select id="chat-provider" disabled={source === 'chatgpt_share'} value={source === 'chatgpt_share' ? 'openai' : provider} onChange={e => setProvider(e.target.value)}>{['other', 'openai', 'anthropic', 'google'].map(item => <option key={item}>{item}</option>)}</select></div><div className="field"><label htmlFor="chat-access">Access mode</label><select id="chat-access" value={source} onChange={e => changeSource(e.target.value as ChatSource)}><option value="pasted_text">Pasted text</option><option value="metadata_only">Metadata only</option><option value="chatgpt_share">Public ChatGPT share link</option></select></div></div>
        {source === 'metadata_only' ? <p className="reason-box" role="note">Metadata-only warning: the URL will not be fetched. No transcript can be evaluated and no risk score is available.</p> : source === 'chatgpt_share' ? <div className="reason-box"><label><input type="checkbox" checked={fetchConsent} onChange={e => setFetchConsent(e.target.checked)} /> I consent to the server contacting ChatGPT to retrieve this public share link.</label><p>Only public share links are supported; no private links, logins, or hidden live tool access. Creation records metadata only; retrieval happens when analysis is requested.</p></div> : <div className="field"><label htmlFor="chat-transcript">Transcript text (128 KiB maximum)</label><textarea id="chat-transcript" value={text} onChange={e => setText(e.target.value)} rows={12} placeholder="Paste chat text to analyze…" /></div>}
      </fieldset>
      {error && <p className="form-error" role="alert">{error}</p>}{source === 'chatgpt_share' && error && session && <div className="reason-box"><p>Public share import did not return an analysis. You can paste the transcript instead.</p><button className="button ghost" type="button" onClick={() => changeSource('pasted_text')}>Use pasted text instead</button></div>}<div className="button-row"><button className="button safe-action" disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button><button className="button ghost" type="button" onClick={reset}>Reset</button></div>
    </form><section className="panel custom-result"><h2>Analysis evidence</h2>
      <p role="status">Status: {busy ? 'analyzing' : analysis?.status || (error ? 'request failed' : session?.status || 'not started')}</p>
       {session && <p>Session: {session.id} · {session.source_type}</p>}
       {analysis?.decision && <div className="reason-box"><strong>Recommendation: {analysis.decision}</strong><p>Retrospective analysis only — not runtime enforcement.</p><ul>{analysis.reasons?.map((reason, index) => <li key={index}>{reason}</li>)}</ul><p>Matched analysis rules: {analysis.policy_matches?.join(', ') || 'None'}</p></div>}
      {analysis ? <div className="result-content"><div className="reason-box"><strong>Risk: {analysis.risk_score === null ? 'Not evaluated' : `${analysis.risk_score}/100`}</strong><p>Source: {analysis.source_trust_level} · {analysis.executed ? 'executed' : 'not executed'}</p>{analysis.limitation && <p>{analysis.limitation}</p>}</div>
        {analysis.status === 'evaluated' && <><h3>Redacted transcript</h3><pre className="redacted-preview">{analysis.redacted_preview}</pre><h3>Findings</h3>{analysis.findings.map((finding, i) => <div className="reason-box" key={i}><strong>{finding.detector.replace(/_/g, ' ')}: {finding.detected ? 'detected' : 'not detected'}</strong><p>{finding.severity} · {Math.round(finding.confidence * 100)}% confidence</p><p>{[...finding.indicators, ...finding.categories, ...finding.reasons].join(' · ')}</p>{finding.redacted_preview && <pre>{finding.redacted_preview}</pre>}</div>)}<p>Tool-call instructions: {analysis.tool_call_instructions_detected ? 'detected in text' : 'not detected in text'}. This does not establish that a tool ran.</p><h3>Detected URL origins</h3>{analysis.urls_detected.length ? <ul>{analysis.urls_detected.map((value, i) => <li key={i}>{value}</li>)}</ul> : <p>No URL origins returned.</p>}</>}
      </div> : !busy && <p>No analysis returned yet.</p>}
    </section></div>
    {analysis && <div className="agent-detail">{eventsError && <p role="alert" className="form-error">{eventsError}</p>}<section className="panel evidence-list"><h2>Monitor events</h2>{!events.length && <p>No monitor events returned.</p>}{events.map(event => <details key={event.id}><summary>{event.sequence} · {event.event_type}</summary><pre>{event.redacted_text}</pre><pre>{JSON.stringify(event.payload, null, 2)}</pre></details>)}</section><Evidence title="Chat audit events" items={audit} /></div>}
  </>
}
