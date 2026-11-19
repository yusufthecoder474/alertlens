import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getMetrics } from "../api.js";

export default function Dashboard() {
  const [m, setM] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { getMetrics().then(setM).catch((e) => setError(e.message)); }, []);
  if (error) return <main><p className="notice notice--error" role="alert">Failed to load metrics: {error}</p></main>;
  if (!m) return <main><p className="notice notice--loading">Loading metrics…</p></main>;
  const chartData = [
    { name: "Raw alerts", count: m.total_alerts },
    { name: "Incidents", count: m.total_incidents },
    { name: "Surfaced incidents", count: m.surfaced_incidents },
    { name: "Duplicates", count: m.duplicate_alerts },
  ];
  const targetNotMet = m.headline_reduction_label === "target not met";
  // Headline reduction is only published when the recall target is met;
  // otherwise the label is the string "target not met" — never a number.
  const cards = [
    { label: "Headline reduction", value: m.headline_reduction_label, hero: true, alert: targetNotMet },
    { label: "Alerts in", value: String(m.total_alerts) },
    { label: "Incidents", value: String(m.total_incidents) },
    { label: "Dedup / correlation reduction", value: `${m.dedup_correlation_reduction_pct}%` },
    { label: "After-triage reduction", value: m.after_triage_reduction_pct != null ? `${m.after_triage_reduction_pct}%` : "target not met", alert: m.after_triage_reduction_pct == null },
    { label: "Surfaced incidents", value: String(m.surfaced_incidents) },
    { label: "Suppressed incidents", value: String(m.suppressed_incidents) },
    { label: "Suppression ratio", value: String(m.suppression_ratio) },
    { label: "Median dwell (s)", value: String(m.median_dwell_seconds) },
    { label: "Recall at threshold", value: m.recall_at_threshold ?? "n/a" },
    { label: "False-positive rate", value: m.false_positive_rate ?? "n/a" },
    { label: "Reopen rate", value: m.reopen_rate ?? "n/a" },
  ];
  return (
    <main>
      <h2>Dashboard</h2>
      {targetNotMet && (
        <p className="notice notice--error" role="alert">
          Recall target not met — the headline reduction is withheld, not shown as a number.
          The threshold needs recalibration or more labelled data before reduction can be claimed.
        </p>
      )}
      <div className="kpi-grid">
        {cards.map((c) => (
          <div key={c.label} className={`kpi-card${c.hero ? " kpi-card--hero" : ""}${c.alert ? " kpi-card--alert" : ""}`}>
            <div className="kpi-card__label">{c.label}</div>
            <div className="kpi-card__value">{c.value}</div>
          </div>
        ))}
      </div>
      <section className="chart-card" aria-label="Alerts versus incidents chart">
        <h3>Raw alerts vs incidents</h3>
        <div className="chart-wrap" style={{ minWidth: 320 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="name" /><YAxis />
              <Tooltip /><Legend /><Bar dataKey="count" fill="#2563eb" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </main>
  );
}
