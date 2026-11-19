import { useEffect, useState } from "react";
import { getIncident, postFeedback, reopenIncident, updateStatus } from "../api.js";

export default function Detail({ id }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const load = () => getIncident(id).then(setData).catch((e) => setError(e.message));
  useEffect(() => { load(); }, [id]);
  if (error) return <p role="alert">Failed to load incident: {error}</p>;
  if (!data) return <p>Loading incident…</p>;
  const { incident, alerts } = data;
  const act = async (fn, msg) => { await fn(); setMessage(msg); load(); };
  return (
    <main>
      <h2>{incident.title}</h2>
      {incident.suppressed ? (
        <div role="alert" style={{ border: "1px solid #b45309", background: "#fef3c7", borderRadius: 8, padding: 12 }}>
          <p><strong>This incident was suppressed from the queue.</strong></p>
          <p>{incident.suppression_reason}</p>
          <button onClick={() => act(() => reopenIncident(id), "Incident reopened.")}>Reopen incident</button>
        </div>
      ) : null}
      <p><strong>Priority:</strong> {incident.priority_score.toFixed(2)} | <strong>Status:</strong> {incident.status} | <strong>Severity:</strong> {incident.severity}</p>
      <h3>Evidence package</h3>
      <p><strong>Who:</strong> {incident.src_ip || "unknown"} on host {incident.host || "unknown"}</p>
      <p><strong>When:</strong> {incident.first_seen} → {incident.last_seen}</p>
      <p><strong>What:</strong> {incident.alert_count} distinct alert(s), {incident.duplicate_count} duplicate(s) suppressed</p>
      <p><strong>Why:</strong></p>
      <ul>{incident.factors.map((f) => <li key={f}>{f}</li>)}</ul>
      <p><strong>MITRE ATT&amp;CK:</strong> {incident.mitre_tags.join(", ") || "none mapped"}</p>
      <p><strong>Summary ({incident.summary_source}):</strong> {incident.summary}</p>
      <p><strong>Next action:</strong> see summary above; analyst actions below.</p>
      <h3>Alert timeline</h3>
      <ul>{alerts.map((a) => (
        <li key={a.id}>{a.timestamp} — {a.rule_name} ({a.severity}){a.is_duplicate ? " [duplicate]" : ""}</li>
      ))}</ul>
      <h3>Analyst actions</h3>
      <label>Status <select aria-label="Change status" defaultValue={incident.status}
        onChange={(e) => act(() => updateStatus(id, e.target.value), "Status updated.")}>
        {["new", "in_triage", "investigating", "resolved"].map((s) => <option key={s} value={s}>{s}</option>)}
      </select></label>
      <button onClick={() => act(() => postFeedback(id, "true_positive"), "Marked true positive.")}>Mark true positive</button>
      <button onClick={() => act(() => postFeedback(id, "false_positive"), "Marked false positive.")}>Mark false positive</button>
      {message && <p role="status">{message}</p>}
    </main>
  );
}
