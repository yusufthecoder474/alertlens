import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { getIncident, reopenIncident } from "../api.js";
import Detail from "../pages/Detail.jsx";

const baseIncident = {
  id: 1, title: "PowerShell on web-01", priority_score: 0.9, status: "new",
  severity: "high", alert_count: 3, duplicate_count: 2,
  factors: ["Highest alert severity is high, which raises priority."],
  mitre_tags: ["T1059.001"], summary: "Incident on web-01.", summary_source: "template",
  first_seen: "2026-11-19T09:00:00", last_seen: "2026-11-19T09:10:00",
  suppressed: false, suppression_reason: null,
};

vi.mock("../api.js", () => ({
  getIncident: vi.fn(),
  updateStatus: () => Promise.resolve({}),
  postFeedback: () => Promise.resolve({}),
  reopenIncident: vi.fn(() => Promise.resolve({})),
}));

function mockDetail(incident) {
  getIncident.mockResolvedValue({
    incident,
    alerts: [
      { id: "a1", timestamp: "2026-11-19T09:00:00", rule_name: "Port Scan Detected", severity: "high", is_duplicate: false },
      { id: "a2", timestamp: "2026-11-19T09:01:00", rule_name: "Port Scan Detected", severity: "high", is_duplicate: true },
    ],
  });
}

describe("Detail", () => {
  it("shows the evidence package", async () => {
    mockDetail(baseIncident);
    render(<Detail id="1" />);
    await waitFor(() => expect(screen.getByText("Evidence package")).toBeInTheDocument());
    expect(screen.getByText("PowerShell on web-01")).toBeInTheDocument();
    expect(screen.getByText(/T1059.001/)).toBeInTheDocument();
  });

  it("shows the timeline and marks duplicates", async () => {
    mockDetail(baseIncident);
    render(<Detail id="1" />);
    await waitFor(() => expect(screen.getByText("Alert timeline")).toBeInTheDocument());
    expect(screen.getByText(/\[duplicate\]/)).toBeInTheDocument();
  });

  it("offers analyst actions", async () => {
    mockDetail(baseIncident);
    render(<Detail id="1" />);
    await waitFor(() => expect(screen.getByText("Mark true positive")).toBeInTheDocument());
    expect(screen.getByText("Mark false positive")).toBeInTheDocument();
    expect(screen.getByLabelText("Change status")).toBeInTheDocument();
  });

  it("shows a suppressed banner with the reason and a reopen button", async () => {
    mockDetail({ ...baseIncident, suppressed: true,
      suppression_reason: "ML probability 0.01 below calibrated threshold 0.50 (recall target 0.95); incident suppressed from the queue, not deleted — reopen to triage it." });
    render(<Detail id="1" />);
    await waitFor(() => expect(screen.getByText(/This incident was suppressed/)).toBeInTheDocument());
    expect(screen.getByText(/ML probability 0.01 below calibrated threshold/)).toBeInTheDocument();
    const button = screen.getByText("Reopen incident");
    fireEvent.click(button);
    await waitFor(() => expect(reopenIncident).toHaveBeenCalledWith("1"));
    expect(screen.getByText("Incident reopened.")).toBeInTheDocument();
  });

  it("shows no suppressed banner for a surfaced incident", async () => {
    mockDetail(baseIncident);
    render(<Detail id="1" />);
    await waitFor(() => expect(screen.getByText("Evidence package")).toBeInTheDocument());
    expect(screen.queryByText(/This incident was suppressed/)).not.toBeInTheDocument();
    expect(screen.queryByText("Reopen incident")).not.toBeInTheDocument();
  });
});
