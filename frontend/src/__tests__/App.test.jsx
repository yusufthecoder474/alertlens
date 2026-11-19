import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App, { parseHash } from "../App.jsx";

vi.mock("../api.js", () => ({
  getMetrics: () => Promise.resolve({
    total_alerts: 152, total_incidents: 8, duplicate_alerts: 65,
    alert_reduction_pct: 94.74, suppression_ratio: 0.4276,
    median_dwell_seconds: 6300, recall_at_threshold: 1.0,
    false_positive_rate: null, reopen_rate: null, threshold: 0.95,
  }),
  getIncidents: () => Promise.resolve([]),
  getIncident: () => Promise.resolve({ incident: { id: 1, title: "Test incident", priority_score: 0.9, status: "new", severity: "high", alert_count: 3, duplicate_count: 2, factors: ["f1"], mitre_tags: ["T1046"], summary: "s", summary_source: "template", first_seen: "2026-11-19", last_seen: "2026-11-19" }, alerts: [] }),
  updateStatus: () => Promise.resolve({}),
  reopenIncident: () => Promise.resolve({}),
  postFeedback: () => Promise.resolve({}),
}));

describe("parseHash", () => {
  it("routes dashboard, queue and detail", () => {
    expect(parseHash("#/")).toEqual({ page: "dashboard" });
    expect(parseHash("#/queue")).toEqual({ page: "queue" });
    expect(parseHash("#/incident/7")).toEqual({ page: "detail", id: "7" });
  });
});

describe("App", () => {
  it("renders the AlertLens header and nav", () => {
    render(<App />);
    expect(screen.getByText("AlertLens")).toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Incident Queue")).toBeInTheDocument();
  });
});
