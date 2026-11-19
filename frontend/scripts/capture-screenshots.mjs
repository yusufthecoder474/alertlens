/**
 * Capture deterministic AlertLens screenshots + docs/SCREENSHOTS.md.
 *
 * One command (from the repo root, or `npm run screenshots` in frontend/):
 *   1. starts the API on a temp SQLite DB (known API key) and seeds it
 *      from data/sample_alerts.csv,
 *   2. serves the frontend with the Vite dev server (proxies /api),
 *   3. captures PNGs into docs/screenshots/ (desktop 1440x900, mobile
 *      390x844, reduced motion, fixed seeded data so output is stable),
 *   4. writes docs/SCREENSHOTS.md with live numbers from /metrics and
 *      /incidents — never hardcoded.
 *
 * Requires: Python deps installed (the API runs from the repo venv when
 * present, else `python3`/`python` on PATH) and Playwright Chromium:
 *   cd frontend && npm ci && npx playwright install chromium
 * Then: npm run screenshots
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND = path.resolve(__dirname, "..");
const ROOT = path.resolve(FRONTEND, "..");
const API_URL = "http://localhost:8000";
const WEB_URL = "http://localhost:5173";
const API_KEY = "shot-test-key";
const SHOTS = path.join(ROOT, "docs", "screenshots");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function pythonCmd() {
  // Repo venv first (Linux/macOS, then Windows layout), else PATH python.
  for (const p of [".venv/bin/python", ".venv/Scripts/python.exe"]) {
    if (fs.existsSync(path.join(ROOT, p))) return path.join(ROOT, p);
  }
  return process.platform === "win32" ? "python" : "python3";
}

function start(cmd, args, opts) {
  // detached: true puts the child in its own process group, so stop()
  // below can kill the whole tree (vite spawns its own children).
  const child = spawn(cmd, args, { ...opts, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (d) => process.stdout.write(`[${opts.name}] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[${opts.name}] ${d}`));
  return child;
}

async function waitFor(url, { timeoutMs = 30000, headers = {} } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url, { headers });
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await sleep(500);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function apiJson(p, opts = {}) {
  const res = await fetch(`${API_URL}${p}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${p} -> ${res.status}`);
  return res.json();
}

async function run(cmd, args, env) {
  await new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: ROOT, env: { ...process.env, ...env }, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))));
  });
}

async function shot(page, url, file, waitText) {
  await page.goto(url, { waitUntil: "networkidle" });
  if (waitText) await page.getByText(waitText, { exact: false }).first().waitFor({ timeout: 15000 });
  await sleep(700); // let the Recharts animation settle
  await page.screenshot({ path: path.join(SHOTS, file) });
  console.log(`captured ${file}`);
}

async function main() {
  fs.mkdirSync(SHOTS, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "alertlens-shots-"));
  const dbPath = path.join(tmp, "alertlens.db");
  const apiEnv = {
    DATABASE_URL: `sqlite:///${dbPath}`, API_KEY, ENV: "dev",
    RATE_LIMIT_PER_MINUTE: "10000",
  };
  const api = start(pythonCmd(), ["-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000"],
    { cwd: ROOT, env: { ...process.env, ...apiEnv }, name: "api" });
  // Vite directly (not via npm): killing the child must kill the server —
  // `npm run dev` leaves the vite child alive on SIGTERM and the next run
  // then fails with "Port 5173 is already in use".
  const web = start("npx", ["vite", "--port", "5173", "--strictPort"],
    { cwd: FRONTEND, env: { ...process.env, API_KEY }, name: "web" });
  try {
    await waitFor(`${API_URL}/health`);
    await run(pythonCmd(), ["scripts/load_csv.py", "data/sample_alerts.csv"],
      { API_URL, API_KEY, DATABASE_URL: apiEnv.DATABASE_URL });
    await waitFor(WEB_URL);

    const metrics = await apiJson("/metrics");
    const incidents = (await apiJson("/incidents?include_suppressed=true"))
      .sort((a, b) => b.priority_score - a.priority_score);
    const top = incidents[0];
    const n = (x) => (x == null ? "n/a" : String(x));
    const headline = metrics.headline_reduction_label;
    const collapsed = `${metrics.total_alerts} alerts collapsed into ${metrics.total_incidents} incidents ` +
      `(${metrics.surfaced_incidents} surfaced, ${metrics.suppressed_incidents} suppressed)`;

    let afterIncident = null;
    const browser = await chromium.launch();
    try {
      const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
      const page = await desktop.newPage();
      await shot(page, `${WEB_URL}/#/`, "dashboard-desktop.png", "Headline reduction");
      await shot(page, `${WEB_URL}/#/queue`, "queue-desktop.png", "Incident Queue");
      await page.getByLabel("Show suppressed").check();
      await sleep(700);
      await page.screenshot({ path: path.join(SHOTS, "queue-show-suppressed.png") });
      console.log("captured queue-show-suppressed.png");
      await shot(page, `${WEB_URL}/#/incident/${top.id}`, "incident-detail.png", "Evidence package");
      // Mark the top incident true positive and move it to investigating,
      // then re-capture the detail page and the dashboard.
      await apiJson(`/incidents/${top.id}/feedback`, {
        method: "POST", body: JSON.stringify({ label: "true_positive", note: "screenshot demo" }),
      });
      await apiJson(`/incidents/${top.id}/status`, {
        method: "PATCH", body: JSON.stringify({ status: "investigating" }),
      });
      afterIncident = (await apiJson(`/incidents/${top.id}`)).incident;
      await shot(page, `${WEB_URL}/#/incident/${top.id}`, "incident-detail-after-feedback.png", "Evidence package");
      await shot(page, `${WEB_URL}/#/`, "dashboard-after-feedback.png", "Headline reduction");
      await desktop.close();

      const mobile = await browser.newContext({
        viewport: { width: 390, height: 844 }, isMobile: true, reducedMotion: "reduce",
      });
      const mpage = await mobile.newPage();
      await shot(mpage, `${WEB_URL}/#/`, "dashboard-mobile.png", "Headline reduction");
      await shot(mpage, `${WEB_URL}/#/queue`, "queue-mobile.png", "Incident Queue");
      await shot(mpage, `${WEB_URL}/#/incident/${top.id}`, "detail-mobile.png", "Evidence package");
      await mobile.close();
    } finally {
      await browser.close();
    }

    const afterMetrics = await apiJson("/metrics");
    const lines = [
      "# AlertLens — screenshots",
      "",
      "Captured by `npm run screenshots` (frontend/scripts/capture-screenshots.mjs) against a",
      "temp SQLite database seeded from `data/sample_alerts.csv` with a known API key. All",
      "numbers below come from live `/metrics` and `/incidents` responses in that run —",
      "nothing here is hardcoded.",
      "",
      `Seeded run: ${collapsed}; headline reduction ${headline}; recall at threshold ${n(metrics.recall_at_threshold)}.`,
      `Top incident after feedback: "${afterIncident.title}" is now ${afterIncident.status} with analyst label ${afterIncident.analyst_label ?? "none"}; ` +
        `dashboard after feedback still shows ${afterMetrics.total_incidents} incidents (${afterMetrics.surfaced_incidents} surfaced).`,
      "",
      "## Dashboard — desktop",
      "",
      "![Dashboard — desktop](screenshots/dashboard-desktop.png)",
      "",
      `The KPI grid leads with the headline reduction (${headline}) and the counts behind it — ` +
        `${metrics.total_alerts} raw alerts, ${metrics.total_incidents} incidents, ${metrics.surfaced_incidents} surfaced ` +
        `and ${metrics.suppressed_incidents} suppressed. An analyst sees in one glance how much noise was removed ` +
        `and whether the recall target was met; the chart below makes the raw-alerts-to-incidents funnel concrete.`,
      "",
      "## Incident queue — desktop",
      "",
      "![Incident queue — desktop](screenshots/queue-desktop.png)",
      "",
      `The queue is the working list: ${metrics.surfaced_incidents} surfaced incidents sorted by priority, ` +
        `each with a host, a priority bar, and severity/status badges. Sorting by priority instead of time ` +
        `is the point of the product — the most dangerous incident is first, not the loudest alert.`,
      "",
      "## Queue — show suppressed",
      "",
      "![Queue — show suppressed](screenshots/queue-show-suppressed.png)",
      "",
      (metrics.suppressed_incidents > 0
        ? `With "Show suppressed" on, the ${metrics.suppressed_incidents} suppressed incident(s) appear muted with a ` +
          `suppressed badge. Suppression is auditable, not deletion: an analyst can find and reopen anything the ` +
          `threshold hid, which is what makes the false-negative budget trustworthy.`
        : `No incident was suppressed in this seeded run, so the "Show suppressed" toggle reveals the same ` +
          `queue with nothing muted — the toggle exists for runs where the threshold does hide incidents, ` +
          `and suppression is auditable, not deletion: an analyst can find and reopen anything the ` +
          `threshold hid, which is what makes the false-negative budget trustworthy.`),
      "",
      "## Incident detail",
      "",
      "![Incident detail](screenshots/incident-detail.png)",
      "",
      `The evidence package for the top incident ("${top.title}", priority ${top.priority_score.toFixed(2)}) ` +
        `answers who, what, when, where and why on one screen, with MITRE ATT&CK chips and a vertical alert ` +
        `timeline. That is the whole triage decision in one place — Devo's survey found analysts spend most ` +
        `of their time assembling exactly this, so the product assembles it for them.`,
      "",
      "## Incident detail — after feedback",
      "",
      "![Incident detail — after feedback](screenshots/incident-detail-after-feedback.png)",
      "",
      `The same incident after an analyst marked it true positive and moved it to investigating. ` +
        `Feedback is stored per incident and feeds the retrain script, so the next calibration learns ` +
        `from this environment's benign behaviour instead of only from synthetic data.`,
      "",
      "## Dashboard — after feedback",
      "",
      "![Dashboard — after feedback](screenshots/dashboard-after-feedback.png)",
      "",
      `The dashboard after the feedback action: the queue counts are unchanged in shape ` +
        `(${afterMetrics.total_incidents} incidents, ${afterMetrics.surfaced_incidents} surfaced), but the ` +
        `false-positive rate and reopen rate now reflect a real analyst decision — the metrics are ` +
        `a live view of the queue, not a static report.`,
      "",
      "## Dashboard — mobile (390px)",
      "",
      "![Dashboard — mobile](screenshots/dashboard-mobile.png)",
      "",
      `The same dashboard at 390px wide: KPI cards stack in one column and the chart card keeps a ` +
        `minimum width so it never renders at zero width. A SOC analyst checking the queue on a phone ` +
        `still sees the headline number first, with no horizontal scrolling.`,
      "",
      "## Queue — mobile (390px)",
      "",
      "![Queue — mobile](screenshots/queue-mobile.png)",
      "",
      `The queue at 390px: the table becomes stacked cards, one per incident, with the title, host, ` +
        `priority bar and badges still legible. Triage on a small screen stays possible because the ` +
        `layout adapts instead of shrinking the table.`,
      "",
      "## Incident detail — mobile (390px)",
      "",
      "![Incident detail — mobile](screenshots/detail-mobile.png)",
      "",
      `The evidence package at 390px: sections stack, MITRE chips wrap, and the timeline stays ` +
        `vertical. Nothing is cut off — the analyst can still read the why and act on it.`,
      "",
    ];
    fs.writeFileSync(path.join(ROOT, "docs", "SCREENSHOTS.md"), lines.join("\n"));
    console.log("wrote docs/SCREENSHOTS.md");
  } finally {
    // Kill each server's whole process group (SIGTERM, then SIGKILL):
    // killing only the direct child orphans vite, which holds our stdio
    // pipes open and keeps this process from ever exiting.
    for (const child of [api, web]) {
      try { process.kill(-child.pid, "SIGTERM"); } catch { /* already dead */ }
      try { child.kill("SIGTERM"); } catch { /* already dead */ }
    }
    await sleep(1000);
    for (const child of [api, web]) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* already dead */ }
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
