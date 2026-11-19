"""Incident summaries: deterministic template by default, optional LLM.

The LLM path only runs when LLM_ENABLED=true and an OPENAI_API_KEY is set.
Any failure or timeout falls back to the template, and the caller records
which source produced the summary.
"""
import httpx

from api.config import settings

TEMPLATE = (
    "Incident on {host} ({src_ip}): {n} distinct alert(s) between {start} and {end}. "
    "Top rule: {rule}. MITRE techniques: {mitre}. Priority {priority:.2f}. "
    "Recommended next action: {action}."
)


def next_action(priority: float, ml_probability: float) -> str:
    """Plain next step an analyst can act on."""
    if priority >= 0.7 or ml_probability >= 0.7:
        return "isolate the host and start containment"
    if priority >= 0.4:
        return "triage the alert timeline and check the host"
    return "monitor; resolve as false positive if the timeline is benign"


def template_summary(incident: dict, alerts: list[dict]) -> str:
    """Deterministic summary built only from incident data."""
    mitre = ", ".join(sorted({t for t in incident.get("mitre_tags", [])})) or "none mapped"
    top_rule = max((a.get("rule_name", "") for a in alerts), key=len, default="unknown")
    return TEMPLATE.format(
        host=incident.get("host") or "unknown host",
        src_ip=incident.get("src_ip") or "unknown IP",
        n=len(alerts),
        start=str(incident.get("first_seen", "")),
        end=str(incident.get("last_seen", "")),
        rule=top_rule,
        mitre=mitre,
        priority=float(incident.get("priority_score", 0.0)),
        action=next_action(float(incident.get("priority_score", 0.0)), float(incident.get("ml_probability", 0.0))),
    )


def llm_summary(incident: dict, alerts: list[dict]) -> tuple[str, str]:
    """Return (summary, source). LLM only when enabled + keyed; else template."""
    text = template_summary(incident, alerts)
    if not settings.llm_enabled or not settings.openai_api_key:
        return text, "template"
    try:
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"Summarise this SOC incident in 3 sentences: {text}"}],
                "max_tokens": 200,
            },
            timeout=5.0,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        return content or text, "llm"
    except Exception:
        return text, "template"
