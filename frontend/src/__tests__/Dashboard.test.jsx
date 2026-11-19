import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { getMetrics } from "../api.js";
import Dashboard from "../pages/Dashboard.jsx";

vi.mock("../api.js", () => ({ getMetrics: vi.fn() }));

const met = {
  total_alerts: 152, total_incidents: 8, duplicate_alerts: 65,
  alert_reduction_pct: 94.74, dedup_correlation_reduction_pct: 94.74,
  after_triage_reduction_pct: 94.74, headline_reduction_pct: 94.74,
  headline_reduction_label: "94.74%", surfaced_incidents: 7, suppressed_incidents: 1,
  suppression_ratio: 0.4276, median_dwell_seconds: 6300, recall_at_threshold: 1.0,
  false_positive_rate: null, reopen_rate: null, threshold: 0.95,
};

describe("Dashboard", () => {
  it("shows KPI cards including surfaced vs suppressed", async () => {
    getMetrics.mockResolvedValue(met);
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText("Headline reduction")).toBeInTheDocument());
    // Headline, dedup/correlation and after-triage cards all show 94.74% here.
    expect(screen.getAllByText("94.74%")).toHaveLength(3);
    expect(screen.getByText("Dedup / correlation reduction")).toBeInTheDocument();
    expect(screen.getByText("Surfaced incidents")).toBeInTheDocument();
    expect(screen.getByText("Suppressed incidents")).toBeInTheDocument();
    expect(screen.getByText("0.4276")).toBeInTheDocument();
  });

  it("shows the chart heading and a surfaced-incidents bar", async () => {
    getMetrics.mockResolvedValue(met);
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText("Raw alerts vs incidents")).toBeInTheDocument());
    expect(screen.getByText("Surfaced incidents")).toBeInTheDocument();
  });

  it("shows 'target not met' when recall is below target", async () => {
    getMetrics.mockResolvedValue({
      ...met, after_triage_reduction_pct: null, headline_reduction_pct: null,
      headline_reduction_label: "target not met", recall_at_threshold: 0.5,
    });
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText("Headline reduction")).toBeInTheDocument());
    // Headline + after-triage cards both say "target not met"; the
    // dedup/correlation card still shows its (unconditional) number.
    expect(screen.getAllByText("target not met")).toHaveLength(2);
    expect(screen.getByText("Dedup / correlation reduction")).toBeInTheDocument();
    expect(screen.getAllByText("94.74%")).toHaveLength(1);
  });

  it("shows a loading state first", () => {
    getMetrics.mockReturnValue(new Promise(() => {}));
    render(<Dashboard />);
    expect(screen.getByText(/Loading metrics/)).toBeInTheDocument();
  });
});
