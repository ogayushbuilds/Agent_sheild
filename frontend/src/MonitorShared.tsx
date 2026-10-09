export function ScreenHeading({ title, detail }: { title: string; detail: string }) {
  return <div className="section-heading"><div><div className="eyebrow">Live API data</div><h1>{title}</h1><p>{detail}</p></div></div>
}
export function Evidence({ title, items }: { title: string; items: { id: string; event_type: string; payload: Record<string, unknown> }[] }) {
  return <section className="panel evidence-list"><h2>{title}</h2>{!items.length && <p>No {title.toLowerCase()} returned.</p>}{items.map(item => <details key={item.id}><summary>{item.event_type}</summary><pre>{JSON.stringify(item.payload, null, 2)}</pre></details>)}</section>
}
export const message = (error: unknown) => error instanceof Error ? error.message : 'API request failed. Please retry.'
