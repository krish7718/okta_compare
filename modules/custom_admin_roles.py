import json

from scripts.extract_admin_roles import get_custom_admin_roles

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def compare_custom_admin_roles(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare custom admin roles between Env A and Env B.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    rolesA = get_custom_admin_roles(baseA, envA_token, limit=limit) or []
    rolesB = get_custom_admin_roles(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {r.get("label") or r.get("name") or r.get("id"): r for r in rolesA}
    dictB = {r.get("label") or r.get("name") or r.get("id"): r for r in rolesB}

    for name, roleA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Custom Admin Roles",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Admin Access",
                "Recommended Action": f"Create custom role '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        roleB = dictB[name]
        if _signature(roleA) != _signature(roleB):
            diffs.append({
                "Category": "Custom Admin Roles",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Admin Role Drift",
                "Recommended Action": f"Align custom role settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Custom Admin Roles",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Custom Admin Roles",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Admin Role",
                "Recommended Action": f"Review extra custom role '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
