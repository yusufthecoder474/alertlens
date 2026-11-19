/** Minimal API client. The browser never sees the API key: requests go to
 * the same-origin "/api" path; in Docker, nginx reverse-proxies /api/ to the
 * API service and injects X-API-Key server-side (see
 * frontend/nginx.conf.template); in local dev, Vite proxies /api to the
 * API (see vite.config.js). No key is baked into the
 * bundle and no build-time key variable is needed. */
const BASE = "/api";

export async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
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
