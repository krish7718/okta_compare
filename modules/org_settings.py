import json

from scripts.extract_org_settings import get_org_settings

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "expiresAt", "subdomain"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _stringify(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def compare_org_settings(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compare org general settings between Env A and Env B.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    settingsA = get_org_settings(baseA, envA_token)
    settingsB = get_org_settings(baseB, envB_token)

    diffs = []
    matches = []

    if not settingsA and not settingsB:
        return diffs, matches

    if not settingsA:
        diffs.append({
            "Category": "Org General Settings",
            "Object": "Org Settings",
            "Attribute": "-",
            "Env A Value": "Missing",
            "Env B Value": "Exists",
            "Difference Type": "Missing in Env A",
            "Impact": "Org Profile",
            "Recommended Action": "Review org general settings in Env A",
            "Priority": "🔴 Critical"
        })
        return diffs, matches

    if not settingsB:
        diffs.append({
            "Category": "Org General Settings",
            "Object": "Org Settings",
            "Attribute": "-",
            "Env A Value": "Exists",
            "Env B Value": "Missing",
            "Difference Type": "Missing in Env B",
            "Impact": "Org Profile",
            "Recommended Action": "Review org general settings in Env B",
            "Priority": "🔴 Critical"
        })
        return diffs, matches

    cleanA = _sanitize(settingsA)
    cleanB = _sanitize(settingsB)
    keys = sorted(set(cleanA.keys()) | set(cleanB.keys()))

    for key in keys:
        valA = cleanA.get(key)
        valB = cleanB.get(key)
        if _stringify(valA) != _stringify(valB):
            diffs.append({
                "Category": "Org General Settings",
                "Object": "Org Settings",
                "Attribute": key,
                "Env A Value": valA if valA is not None else "Missing",
                "Env B Value": valB if valB is not None else "Missing",
                "Difference Type": "Mismatch",
                "Impact": "Org Profile",
                "Recommended Action": f"Align org setting '{key}' across environments",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Org General Settings",
                "Object": "Org Settings",
                "Attribute": key,
                "Value": valA
            })

    return diffs, matches
