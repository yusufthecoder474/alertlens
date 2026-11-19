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
  if (error) return <p role="alert">Failed to load incidents: {error}</p>;
  return (
    <main>
      <h2>Incident Queue</h2>
      <label>Status <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
        <option value="">All</option><option value="new">new</option><option value="in_triage">in_triage</option>
        <option value="investigating">investigating</option><option value="resolved">resolved</option>
      </select></label>
      <label> Sort <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort by">
        <option value="priority">Priority</option><option value="recent">Most recent</option>
      </select></label>
      <label> <input type="checkbox" checked={showSuppressed}
        onChange={(e) => setShowSuppressed(e.target.checked)} /> Show suppressed</label>
      {incidents.length === 0 ? <p>No incidents found.</p> : (
        <ul>
          {incidents.map((i) => (
            <li key={i.id}>
              <a href={`#/incident/${i.id}`}>{i.title}</a>
              {" — priority "}{i.priority_score.toFixed(2)}{" — "}{i.status}
              {" — "}{i.severity}
              {i.suppressed ? <span> — suppressed</span> : null}
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
