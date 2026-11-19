import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { getIncidents } from "../api.js";
import Queue from "../pages/Queue.jsx";

const rows = [
  { id: 1, title: "PowerShell on web-01", priority_score: 0.9, status: "new", severity: "high", last_seen: "2026-11-19T09:10:00", suppressed: false },
  { id: 2, title: "Registry on workstation-02", priority_score: 0.3, status: "new", severity: "low", last_seen: "2026-11-19T09:05:00", suppressed: false },
  { id: 3, title: "Registry noise on workstation-03", priority_score: 0.1, status: "new", severity: "low", last_seen: "2026-11-19T09:04:00", suppressed: true, suppression_reason: "ML probability 0.01 below calibrated threshold 0.50" },
];
// Mock simulates the API: suppressed rows are hidden unless include_suppressed=true.
vi.mock("../api.js", () => ({
  getIncidents: vi.fn((status, includeSuppressed) =>
    Promise.resolve(includeSuppressed ? rows : rows.filter((r) => !r.suppressed))),
}));

describe("Queue", () => {
  it("lists incidents sorted by priority by default", async () => {
    render(<Queue />);
    const rows = await waitFor(() => screen.getAllByRole("row"));
    // First row is the table header; the next two are incidents.
    expect(rows[1]).toHaveTextContent("PowerShell on web-01");
    expect(rows[2]).toHaveTextContent("Registry on workstation-02");
  });

  it("offers status filter and sort controls", async () => {
    render(<Queue />);
    await waitFor(() => screen.getByText("PowerShell on web-01"));
    expect(screen.getByLabelText("Filter by status")).toBeInTheDocument();
    expect(screen.getByLabelText("Sort by")).toBeInTheDocument();
  });

  it("hides suppressed incidents by default and shows them with the toggle", async () => {
    render(<Queue />);
    await waitFor(() => expect(screen.getByText("PowerShell on web-01")).toBeInTheDocument());
    expect(screen.queryByText(/Registry noise on workstation-03/)).not.toBeInTheDocument();
    expect(getIncidents).toHaveBeenCalledWith("", false);
    fireEvent.click(screen.getByLabelText("Show suppressed"));
    await waitFor(() => expect(screen.getByText(/Registry noise on workstation-03/)).toBeInTheDocument());
    expect(getIncidents).toHaveBeenCalledWith("", true);
    // Shown suppressed rows carry a "suppressed" badge.
    expect(screen.getByText(/Registry noise on workstation-03/).closest("tr")).toHaveTextContent("suppressed");
  });
});
