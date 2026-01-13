import json

from scripts.extract_security_settings import get_security_general_settings

_SKIP_KEYS = {"_links", "created", "lastUpdated"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def compare_security_general_settings(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compare security general settings between Env A and Env B.
    Returns (diffs, matches).
    """
    settingsA = get_security_general_settings(envA_domain, envA_token)
    settingsB = get_security_general_settings(envB_domain, envB_token)

    diffs = []
    matches = []

    checks = [
        ("Threats Configuration", "threats_configuration"),
        ("ThreatInsight Settings", "threatinsight"),
        ("Security Notifications", "security_notifications"),
        ("Captcha", "captcha"),
        ("User Enumeration", "user_enumeration"),
        ("User Lockout", "user_lockout"),
        ("Authenticator Settings", "authenticator_settings"),
    ]

    for label, key in checks:
        valA = settingsA.get(key)
        valB = settingsB.get(key)
        if valA is None and valB is None:
            matches.append({
                "Category": "Security General Settings",
                "Object": label,
                "Attribute": "Settings",
                "Value": "Not Available"
            })
            continue
        if valA is None or valB is None:
            diffs.append({
                "Category": "Security General Settings",
                "Object": label,
                "Attribute": "Settings",
                "Env A Value": "Not Available" if valA is None else "Available",
                "Env B Value": "Not Available" if valB is None else "Available",
                "Difference Type": "Mismatch",
                "Impact": "Security Drift",
                "Recommended Action": f"Ensure {label.lower()} settings are accessible in both environments",
                "Priority": "🟠 Medium"
            })
            continue
        if _signature(valA) != _signature(valB):
            diffs.append({
                "Category": "Security General Settings",
                "Object": label,
                "Attribute": "Settings",
                "Env A Value": "Did not match",
                "Env B Value": "Did not match",
                "Difference Type": "Mismatch",
                "Impact": "Security Drift",
                "Recommended Action": f"Align {label.lower()} settings between environments",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Security General Settings",
                "Object": label,
                "Attribute": "Settings",
                "Value": "Match"
            })

    return diffs, matches
