import { useEffect, useState } from "react";
import { getIncident, postFeedback, reopenIncident, updateStatus } from "../api.js";

export default function Detail({ id }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const load = () => getIncident(id).then(setData).catch((e) => setError(e.message));
  useEffect(() => { load(); }, [id]);
  if (error) return <main><p className="notice notice--error" role="alert">Failed to load incident: {error}</p></main>;
  if (!data) return <main><p className="notice notice--loading">Loading incident…</p></main>;
  const { incident, alerts } = data;
  const act = async (fn, msg) => {
    setBusy(true);
    try { await fn(); setMessage(msg); await load(); }
    catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  return (
    <main>
      <h2>{incident.title}</h2>
      {incident.suppressed ? (
        <div className="suppressed-banner" role="alert">
          <p><strong>This incident was suppressed from the queue.</strong></p>
          <p>{incident.suppression_reason}</p>
          <button className="button--primary" disabled={busy} onClick={() => act(() => reopenIncident(id), "Incident reopened.")}>Reopen incident</button>
        </div>
      ) : null}
      <section className="evidence-card" aria-label="Evidence package">
        <h3>Evidence package</h3>
        <dl className="evidence-grid">
          <div className="evidence-section"><dt>Who</dt><dd>{incident.src_ip || "unknown"} on host {incident.host || "unknown"}</dd></div>
          <div className="evidence-section"><dt>What</dt><dd>{incident.alert_count} distinct alert(s), {incident.duplicate_count} duplicate(s) suppressed</dd></div>
          <div className="evidence-section"><dt>When</dt><dd>{incident.first_seen} → {incident.last_seen}</dd></div>
          <div className="evidence-section"><dt>Where</dt><dd>Host {incident.host || "unknown"} ({incident.src_ip || "unknown"}) — priority {incident.priority_score.toFixed(2)}, status {incident.status}, severity {incident.severity}</dd></div>
          <div className="evidence-section"><dt>Why</dt><dd><ul>{incident.factors.map((f) => <li key={f}>{f}</li>)}</ul></dd></div>
          <div className="evidence-section"><dt>Next action</dt><dd>See summary below; analyst actions at the bottom of this page.</dd></div>
        </dl>
        <p><strong>MITRE ATT&amp;CK:</strong></p>
        {incident.mitre_tags.length ? (
          <ul className="chip-list">{incident.mitre_tags.map((t) => <li key={t} className="chip">{t}</li>)}</ul>
        ) : <p>none mapped</p>}
        <p><strong>Summary ({incident.summary_source}):</strong> {incident.summary}</p>
      </section>
      <section className="timeline-card" aria-label="Alert timeline">
        <h3>Alert timeline</h3>
        <ol className="timeline">{alerts.map((a) => (
          <li key={a.id}><time>{a.timestamp}</time> — {a.rule_name} ({a.severity}){a.is_duplicate ? " [duplicate]" : ""}</li>
        ))}</ol>
      </section>
      <section className="actions-card" aria-label="Analyst actions">
        <h3>Analyst actions</h3>
        <div className="actions-row">
          <label>Status <select aria-label="Change status" value={incident.status} disabled={busy}
            onChange={(e) => act(() => updateStatus(id, e.target.value), "Status updated.")}>
            {["new", "in_triage", "investigating", "resolved"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select></label>
          <button disabled={busy} onClick={() => act(() => postFeedback(id, "true_positive"), "Marked true positive.")}>Mark true positive</button>
          <button disabled={busy} onClick={() => act(() => postFeedback(id, "false_positive"), "Marked false positive.")}>Mark false positive</button>
        </div>
        {message && <p className="toast" role="status">{message}</p>}
      </section>
    </main>
  );
}
