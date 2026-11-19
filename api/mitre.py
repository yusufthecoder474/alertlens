"""Hand-made rule -> MITRE ATT&CK technique map and asset criticality.

Only 12 rules are mapped on purpose: a small, auditable map an analyst can
read beats a large auto-generated one nobody trusts.
"""
RULE_TO_MITRE: dict[str, str] = {
    "Suspicious PowerShell": "T1059.001",
    "Mimikatz Credential Dump": "T1003.001",
    "Unusual Outbound Traffic": "T1048",
    "Failed Login Burst": "T1110",
    "Port Scan Detected": "T1046",
    "Malware Signature Match": "T1204.002",
    "Lateral Movement SMB": "T1021.002",
    "DNS Tunnelling Suspected": "T1071.004",
    "Ransomware File Encryption": "T1486",
    "Privilege Escalation Attempt": "T1068",
    "Suspicious Registry Change": "T1112",
    "Data Exfiltration Large Upload": "T1041",
}

SEVERITY_WEIGHT: dict[str, float] = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

# Asset criticality (0-1). Unknown hosts default to 0.5; edit this map, not code.
ASSET_CRITICALITY: dict[str, float] = {
    "dc-01": 1.0,
    "db-01": 0.9,
    "web-01": 0.7,
    "web-02": 0.7,
    "workstation-01": 0.4,
    "workstation-02": 0.4,
    "workstation-03": 0.4,
}


def mitre_for_rule(rule_name: str) -> str | None:
    """Return the MITRE technique id for a rule, or None if unmapped."""
    return RULE_TO_MITRE.get(rule_name)


def asset_criticality(host: str | None) -> float:
    """Return asset criticality for a host (0.5 default for unknown hosts)."""
    if not host:
        return 0.5
    return ASSET_CRITICALITY.get(host, 0.5)
