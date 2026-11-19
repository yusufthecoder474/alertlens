import { describe, expect, it, vi } from "vitest";
import { api, getMetrics, postFeedback } from "../api.js";

// The browser must never carry the API key: requests go to same-origin
// /api (nginx injects X-API-Key server-side in Docker; Vite proxies /api
// to the API in local dev). These tests assert the request shape, not the
// proxy itself (the proxy is asserted end-to-end by scripts/docker_smoke.py).
describe("api client", () => {
  it("calls same-origin /api/metrics with no X-API-Key header", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ total_alerts: 0 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await getMetrics();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/metrics",
      expect.objectContaining({
        headers: expect.not.objectContaining({ "X-API-Key": expect.anything() }),
      }),
    );
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["X-API-Key"]).toBeUndefined();
    expect(headers["Content-Type"]).toBe("application/json");
    vi.unstubAllGlobals();
  });

  it("posts feedback to /api/incidents/:id/feedback without a key", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });
    vi.stubGlobal("fetch", fetchMock);
    await postFeedback(1, "true_positive", "confirmed");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/incidents/1/feedback");
    expect(fetchMock.mock.calls[0][1].headers["X-API-Key"]).toBeUndefined();
    vi.unstubAllGlobals();
  });

  it("throws a readable error on a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 401, text: async () => "nope" }),
    );
    await expect(api("/metrics")).rejects.toThrow("API 401");
    vi.unstubAllGlobals();
  });
});
