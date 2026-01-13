import json

from scripts.extract_admin_roles import get_resource_sets

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def compare_resource_sets(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare resource sets between Env A and Env B.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    setsA = get_resource_sets(baseA, envA_token, limit=limit) or []
    setsB = get_resource_sets(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {s.get("label") or s.get("name") or s.get("id"): s for s in setsA}
    dictB = {s.get("label") or s.get("name") or s.get("id"): s for s in setsB}

    for name, setA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Resource Sets",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Admin Scope",
                "Recommended Action": f"Create resource set '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        setB = dictB[name]
        if _signature(setA) != _signature(setB):
            diffs.append({
                "Category": "Resource Sets",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Resource Set Drift",
                "Recommended Action": f"Align resource set settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Resource Sets",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Resource Sets",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Resource Set",
                "Recommended Action": f"Review extra resource set '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
