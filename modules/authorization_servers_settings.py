import json

from scripts.extract_authorization_servers import (
    get_authorization_servers,
    get_authorization_server_claims,
    get_authorization_server_scopes,
)

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _normalize_named(items, name_key="name"):
    normalized = []
    for item in items or []:
        normalized.append({k: v for k, v in (item or {}).items() if k not in _SKIP_KEYS})
    normalized.sort(key=lambda x: x.get(name_key) or "")
    return normalized


def compare_authorization_servers_settings(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare authorization servers by name; if match, compare settings, claims, and scopes.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    serversA = get_authorization_servers(baseA, envA_token, limit=limit) or []
    serversB = get_authorization_servers(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {s.get("name") or s.get("id"): s for s in serversA}
    dictB = {s.get("name") or s.get("id"): s for s in serversB}

    for name, serverA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Authorization",
                "Recommended Action": f"Create authorization server '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        serverB = dictB[name]
        if _signature(serverA) != _signature(serverB):
            diffs.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Authorization Drift",
                "Recommended Action": f"Align authorization server settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

        claimsA = get_authorization_server_claims(baseA, envA_token, serverA.get("id"), limit=limit)
        claimsB = get_authorization_server_claims(baseB, envB_token, serverB.get("id"), limit=limit)
        if _signature(_normalize_named(claimsA)) != _signature(_normalize_named(claimsB)):
            diffs.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Claims",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Token Claims Drift",
                "Recommended Action": f"Align claims for authorization server '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Claims",
                "Value": "Match"
            })

        scopesA = get_authorization_server_scopes(baseA, envA_token, serverA.get("id"), limit=limit)
        scopesB = get_authorization_server_scopes(baseB, envB_token, serverB.get("id"), limit=limit)
        if _signature(_normalize_named(scopesA)) != _signature(_normalize_named(scopesB)):
            diffs.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Scopes",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Scope Drift",
                "Recommended Action": f"Align scopes for authorization server '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "Scopes",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Authorization Servers - Settings",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Authorization Server",
                "Recommended Action": f"Review extra authorization server '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
