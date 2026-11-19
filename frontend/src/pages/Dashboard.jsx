import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getMetrics } from "../api.js";

export default function Dashboard() {
  const [m, setM] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { getMetrics().then(setM).catch((e) => setError(e.message)); }, []);
  if (error) return <p role="alert">Failed to load metrics: {error}</p>;
  if (!m) return <p>Loading metrics…</p>;
  const chartData = [
    { name: "Raw alerts", count: m.total_alerts },
    { name: "Incidents", count: m.total_incidents },
    { name: "Surfaced incidents", count: m.surfaced_incidents },
    { name: "Duplicates", count: m.duplicate_alerts },
  ];
  // Headline reduction is only published when the recall target is met;
  // otherwise the label is the string "target not met" — never a number.
  const cards = [
    ["Headline reduction", m.headline_reduction_label],
    ["Dedup / correlation reduction", `${m.dedup_correlation_reduction_pct}%`],
    ["After-triage reduction", m.after_triage_reduction_pct != null ? `${m.after_triage_reduction_pct}%` : "target not met"],
    ["Surfaced incidents", String(m.surfaced_incidents)],
    ["Suppressed incidents", String(m.suppressed_incidents)],
    ["Suppression ratio", String(m.suppression_ratio)],
    ["Median dwell (s)", String(m.median_dwell_seconds)],
    ["Recall at threshold", m.recall_at_threshold ?? "n/a"],
    ["False-positive rate", m.false_positive_rate ?? "n/a"],
    ["Reopen rate", m.reopen_rate ?? "n/a"],
  ];
  return (
    <main>
      <h2>Dashboard</h2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        {cards.map(([label, value]) => (
          <div key={label} style={{ border: "1px solid #ccc", borderRadius: 8, padding: 12 }}>
            <div>{label}</div><strong>{value}</strong>
          </div>
        ))}
      </div>
      <h3>Raw alerts vs incidents</h3>
      <div style={{ height: 300 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="name" /><YAxis />
            <Tooltip /><Legend /><Bar dataKey="count" fill="#2563eb" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </main>
  );
}
