import json

from scripts.extract_trusted_origins import get_trusted_origins

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastedUpdated", "lastedUpdatedBy"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _origin_key(origin):
    return origin.get("name") or origin.get("origin") or origin.get("id")


def compare_trusted_origins(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare trusted origins between Env A and Env B by name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    originsA = get_trusted_origins(baseA, envA_token, limit=limit) or []
    originsB = get_trusted_origins(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_origin_key(o): o for o in originsA}
    dictB = {_origin_key(o): o for o in originsB}

    for name, originA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Trusted Origins",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "CORS/Redirect",
                "Recommended Action": f"Create trusted origin '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        originB = dictB[name]
        if _signature(originA) != _signature(originB):
            diffs.append({
                "Category": "Trusted Origins",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "CORS/Redirect Drift",
                "Recommended Action": f"Align trusted origin settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Trusted Origins",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Trusted Origins",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Origin",
                "Recommended Action": f"Review extra trusted origin '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
