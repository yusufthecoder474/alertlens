/** Minimal API client. API key comes from VITE_API_KEY (never hard-coded);
 * with no key set, requests carry an empty key and the API returns 401. */
const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const KEY = import.meta.env.VITE_API_KEY || "";

export async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", "X-API-Key": KEY, ...(options.headers || {}) },
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
  return res.json();
}

export const getMetrics = () => api("/metrics");
export const getIncidents = (status = "", includeSuppressed = false) => {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (includeSuppressed) params.set("include_suppressed", "true");
  const q = params.toString();
  return api(`/incidents${q ? `?${q}` : ""}`);
};
export const getIncident = (id) => api(`/incidents/${id}`);
export const updateStatus = (id, status) =>
  api(`/incidents/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) });
export const reopenIncident = (id) =>
  api(`/incidents/${id}/reopen`, { method: "POST" });
export const postFeedback = (id, label, note = "") =>
  api(`/incidents/${id}/feedback`, { method: "POST", body: JSON.stringify({ label, note }) });
