"""Plain-English contributing factors for an incident (explainability)."""
from api.mitre import SEVERITY_WEIGHT, asset_criticality, mitre_for_rule


def explain_factors(alerts: list[dict], ml_probability: float | None,
                    duplicate_count: int) -> list[str]:
    """Return the top contributing factors, highest impact first.

    When ``ml_probability`` is None the incident has no flow evidence;
    the factors say so plainly instead of inventing an ML verdict.
    """
    factors: list[str] = []
    severities = [str(a.get("severity", "low")).lower() for a in alerts]
    top_sev = max(severities, key=lambda s: SEVERITY_WEIGHT.get(s, 0.25))
    if SEVERITY_WEIGHT.get(top_sev, 0) >= 0.75:
        factors.append(f"Highest alert severity is {top_sev}, which raises priority.")
    else:
        factors.append(f"Highest alert severity is {top_sev}.")
    host = alerts[0].get("host") if alerts else None
    crit = asset_criticality(host)
    if crit >= 0.9:
        factors.append(f"Host {host} is a critical asset (criticality {crit:.1f}).")
    elif host:
        factors.append(f"Host {host} has asset criticality {crit:.1f}.")
    if ml_probability is None:
        factors.append("No flow evidence was available for these alerts, "
                       "so the ML model did not score them.")
    elif ml_probability >= 0.7:
        factors.append(f"ML model rates these alerts as likely malicious ({ml_probability:.0%}).")
    elif ml_probability >= 0.4:
        factors.append(f"ML model is uncertain about these alerts ({ml_probability:.0%}).")
    else:
        factors.append(f"ML model rates these alerts as likely benign ({ml_probability:.0%}).")
    techniques = sorted({t for a in alerts for t in [mitre_for_rule(a.get("rule_name", ""))] if t})
    if techniques:
        factors.append(f"Matched MITRE ATT&CK techniques: {', '.join(techniques)}.")
    if duplicate_count:
        factors.append(f"{duplicate_count} duplicate alert(s) were suppressed into this incident.")
    factors.append(f"Incident contains {len(alerts)} distinct alert(s).")
    return factors[:5]
