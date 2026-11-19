import { useEffect, useState } from "react";
import { getIncidents } from "../api.js";

export default function Queue() {
  const [incidents, setIncidents] = useState([]);
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("priority");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    getIncidents(status, showSuppressed).then((rows) => {
      const sorted = [...rows].sort((a, b) =>
        sort === "priority" ? b.priority_score - a.priority_score : b.last_seen.localeCompare(a.last_seen));
      setIncidents(sorted);
    }).catch((e) => setError(e.message));
  }, [status, sort, showSuppressed]);
  if (error) return <main><p className="notice notice--error" role="alert">Failed to load incidents: {error}</p></main>;
  return (
    <main>
      <h2>Incident Queue</h2>
      <div className="toolbar">
        <label>Status <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All</option><option value="new">new</option><option value="in_triage">in_triage</option>
          <option value="investigating">investigating</option><option value="resolved">resolved</option>
        </select></label>
        <label> Sort <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort by">
          <option value="priority">Priority</option><option value="recent">Most recent</option>
        </select></label>
        <label className="checkbox"> <input type="checkbox" checked={showSuppressed}
          onChange={(e) => setShowSuppressed(e.target.checked)} aria-label="Show suppressed" /> Show suppressed</label>
      </div>
      {incidents.length === 0 ? <p className="notice">No incidents found.</p> : (
        <div className="table-card">
          <table className="queue-table">
            <thead><tr><th scope="col">Title</th><th scope="col">Host</th><th scope="col">Priority</th><th scope="col">Severity</th><th scope="col">Status</th></tr></thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.id} className={i.suppressed ? "row--suppressed" : undefined}>
                  <td><a href={`#/incident/${i.id}`}>{i.title}</a>{i.suppressed ? <> <span className="badge badge--suppressed">suppressed</span></> : null}</td>
                  <td data-label="Host">{i.host || "unknown"}</td>
                  <td data-label="Priority"><span className="priority-cell">
                    <span className="priority-bar" aria-hidden="true"><span className="priority-bar__fill" style={{ width: `${Math.round(i.priority_score * 100)}%` }} /></span>
                    <span>{i.priority_score.toFixed(2)}</span>
                  </span></td>
                  <td data-label="Severity"><span className={`badge badge--${i.severity}`}>{i.severity}</span></td>
                  <td data-label="Status"><span className="badge">{i.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
