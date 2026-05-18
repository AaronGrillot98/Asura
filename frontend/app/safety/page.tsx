import { getBlockedCapabilities } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function SafetyPage() {
  const blocked = await getBlockedCapabilities();
  return (
    <div>
      <header className="topbar">
        <div>
          <span className="eyebrow">Safety Model</span>
          <h1>Blocked capabilities</h1>
          <p>{blocked.explanation}</p>
        </div>
      </header>

      <section className="panel">
        <div className="panelTitle"><h2>Capabilities Asura refuses to ship</h2></div>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Capability</th>
              <th>Rationale</th>
            </tr>
          </thead>
          <tbody>
            {blocked.capabilities.map((bc) => (
              <tr key={bc.id}>
                <td><code className="inlineCode">{bc.id}</code></td>
                <td><strong>{bc.label}</strong></td>
                <td><small>{bc.rationale}</small></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
