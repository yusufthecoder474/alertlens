
"""Docker smoke test for the composed AlertLens stack.

Checks:
1. GET /health returns 200.
2. GET /metrics without an API key returns 401.
3. Nginx proxies authenticated API requests successfully.
4. Loading sample alerts produces the model-independent metrics
   documented in RESULTS.md Part A.

Model-dependent fields are deliberately not compared because Docker
uses the portable synthetic model, while local evaluation may use UNSW.

Usage:
    $env:API_KEY="your-local-key"
    python scripts/docker_smoke.py
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


# Resolve paths relative to this script, not the current PowerShell directory.
ROOT_DIR = Path(__file__).resolve().parents[1]
RESULTS_PATH = ROOT_DIR / "RESULTS.md"
SAMPLE_CSV = ROOT_DIR / "data" / "sample_alerts.csv"
LOAD_SCRIPT = ROOT_DIR / "scripts" / "load_csv.py"

API_URL = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
WEB_URL = os.environ.get("WEB_URL", "http://localhost:5173").rstrip("/")
API_KEY = os.environ.get("API_KEY", "")


def _get(url: str, key: str | None = None) -> tuple[int, dict]:
    """GET a URL and return its HTTP status and parsed JSON response."""
    request = urllib.request.Request(url)

    if key:
        request.add_header("X-API-Key", key)

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            return response.status, json.loads(body or b"{}")

    except urllib.error.HTTPError as error:
        return error.code, {}

    except urllib.error.URLError as error:
        raise SystemExit(
            f"Could not connect to {url}: {error.reason}"
        ) from error


def _check(name: str, passed: bool, detail: str = "") -> None:
    """Print a check result and stop immediately if it fails."""
    status = "PASS" if passed else "FAIL"
    message = f"  [{status}] {name}"

    if detail:
        message += f" — {detail}"

    print(message)

    if not passed:
        raise SystemExit(f"Docker smoke test FAILED at: {name}")


def _parse_part_a() -> dict[str, float]:
    """Read model-independent Part A metrics from RESULTS.md."""

    if not RESULTS_PATH.is_file():
        raise SystemExit(
            f"Cannot find benchmark results file: {RESULTS_PATH}"
        )

    # Explicit UTF-8 decoding is important on Windows.
    # utf-8-sig also handles files containing a UTF-8 BOM.
    with RESULTS_PATH.open("r", encoding="utf-8-sig") as file:
        text = file.read()

    # Find Part A without relying on the exact dash character.
    section = re.search(
        r"Part A\s*[—–-]\s*demo pipeline"
        r"(?P<body>.*?)(?=Part B\b|\Z)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if section is None:
        raise SystemExit(
            "Could not find the Part A demo pipeline section "
            "in RESULTS.md. Check its heading."
        )

    block = section.group("body")
    fields: dict[str, float] = {}

    for line in block.splitlines():
        match = re.match(
            r"\s+([a-z_]+):\s+([0-9]+(?:\.[0-9]+)?)",
            line,
        )

        if match:
            fields[match.group(1)] = float(match.group(2))

    # Compare only model-independent metrics.
    # Model-dependent scoring fields must not be hard-compared.
    required_fields = [
        "raw_alerts",
        "incidents",
        "duplicates_suppressed",
        "dedup_correlation_reduction_pct",
    ]

    missing = [
        field for field in required_fields if field not in fields
    ]

    if missing:
        raise SystemExit(
            f"RESULTS.md Part A is missing fields: {missing}. "
            "Run benchmark.py and update RESULTS.md."
        )

    return fields


def main() -> None:
    """Execute all Docker smoke-test assertions."""

    if not API_KEY:
        raise SystemExit(
            "API_KEY is not set. Set it in PowerShell before running."
        )

    print("Docker smoke test")

    # 1. Backend health check.
    status, body = _get(f"{API_URL}/health")

    _check(
        "GET /health -> 200",
        status == 200 and body.get("status") == "ok",
        f"got {status} {body}",
    )

    # 2. Backend must reject requests without authentication.
    status, _ = _get(f"{API_URL}/metrics")

    _check(
        "GET /metrics without key -> 401",
        status == 401,
        f"got {status}",
    )

    # 3. Nginx should inject the API key server-side.
    status, _ = _get(f"{WEB_URL}/api/metrics")

    _check(
        "GET web proxy /api/metrics (no key) -> 200",
        status == 200,
        f"got {status}",
    )

    # 4. Load the demo CSV through the real API.
    if not SAMPLE_CSV.is_file():
        raise SystemExit(f"Sample CSV not found: {SAMPLE_CSV}")

    print("Loading data/sample_alerts.csv via the API ...")

    environment = os.environ.copy()
    environment["API_URL"] = API_URL
    environment["API_KEY"] = API_KEY

    subprocess.run(
        [
            sys.executable,
            str(LOAD_SCRIPT),
            str(SAMPLE_CSV),
        ],
        check=True,
        env=environment,
        cwd=ROOT_DIR,
    )

    # 5. Read expected benchmark metrics.
    expected = _parse_part_a()

    # 6. Fetch the real metrics through Nginx.
    status, metrics = _get(f"{WEB_URL}/api/metrics")

    _check(
        "GET web proxy /api/metrics after load -> 200",
        status == 200,
        f"got {status}",
    )

    # Compare only fields independent of the trained ML model.
    comparisons = [
        ("raw_alerts", "total_alerts", 0),
        ("incidents", "total_incidents", 0),
        ("duplicates_suppressed", "duplicate_alerts", 0),
        (
            "dedup_correlation_reduction_pct",
            "dedup_correlation_reduction_pct",
            0.01,
        ),
    ]

    for benchmark_field, metric_field, tolerance in comparisons:
        actual = metrics.get(metric_field)
        wanted = expected[benchmark_field]

        passed = (
            actual is not None
            and abs(float(actual) - wanted) <= tolerance
        )

        _check(
            f"/metrics {metric_field} == "
            f"RESULTS.md Part A {benchmark_field} ({wanted})",
            passed,
            f"got {actual}",
        )

    print()
    print("Docker smoke test: all assertions passed")


if __name__ == "__main__":
    main()
