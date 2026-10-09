import { useState } from 'react'
import { api, setApiKey } from './api'

export default function ApiAccess() {
  const [entry, setEntry] = useState('')
  const [configured, setConfigured] = useState(false)
  return <details className="panel api-access"><summary>Local demo API access</summary><p>This dashboard is a local simulator, not a production authentication boundary. If your backend requires a key, enter it for requests to <code>{api.baseUrl}</code>. The key is held only in memory, never bundled or saved to browser storage; reloading clears it. Retry or refresh the screen after applying a key.</p><form onSubmit={event => { event.preventDefault(); setApiKey(entry); setConfigured(Boolean(entry.trim())); setEntry('') }}><div className="field"><label htmlFor="api-key">Backend API key</label><input id="api-key" type="password" autoComplete="off" value={entry} onChange={event => setEntry(event.target.value)} /></div><div className="button-row"><button className="button ghost">Apply key</button><button className="button ghost" type="button" onClick={() => { setApiKey(''); setEntry(''); setConfigured(false) }}>Clear key</button></div></form><p role="status">{configured ? 'Key configured for this page session.' : 'No API key configured; local demo mode requires none.'}</p></details>
}
