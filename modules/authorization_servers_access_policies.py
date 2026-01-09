import json

from scripts.extract_authorization_servers import (
    get_authorization_servers,
    get_authorization_server_policies,
    get_authorization_server_policy_rules,
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


def _rules_signature(rules):
    normalized = []
    for rule in rules or []:
        normalized.append({
            "name": rule.get("name"),
            "status": rule.get("status"),
            "priority": rule.get("priority"),
            "conditions": rule.get("conditions"),
            "actions": rule.get("actions"),
        })
    normalized.sort(key=lambda r: (r.get("priority") or 0, r.get("name") or ""))
    return _signature(normalized)


def compare_authorization_servers_access_policies(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare authorization server access policies by authorization server name.
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
            continue

        serverB = dictB[name]
        policiesA = get_authorization_server_policies(baseA, envA_token, serverA.get("id"), limit=limit) or []
        policiesB = get_authorization_server_policies(baseB, envB_token, serverB.get("id"), limit=limit) or []

        polA_map = {p.get("name") or p.get("id"): p for p in policiesA}
        polB_map = {p.get("name") or p.get("id"): p for p in policiesB}

        for pol_name, polA in polA_map.items():
            if pol_name not in polB_map:
                diffs.append({
                    "Category": "Authorization Servers - Access Policies",
                    "Object": name,
                    "Attribute": pol_name,
                    "Env A Value": "Exists",
                    "Env B Value": "Missing",
                    "Difference Type": "Missing in Env B",
                    "Impact": "Access Policy Coverage",
                    "Recommended Action": f"Create access policy '{pol_name}' for authorization server '{name}' in Env B",
                    "Priority": "🔴 Critical"
                })
                continue

            polB = polB_map[pol_name]
            rulesA = get_authorization_server_policy_rules(
                baseA, envA_token, serverA.get("id"), polA.get("id"), limit=limit
            )
            rulesB = get_authorization_server_policy_rules(
                baseB, envB_token, serverB.get("id"), polB.get("id"), limit=limit
            )

            if _rules_signature(rulesA) != _rules_signature(rulesB):
                diffs.append({
                    "Category": "Authorization Servers - Access Policies",
                    "Object": name,
                    "Attribute": pol_name,
                    "Env A Value": "Different",
                    "Env B Value": "Different",
                    "Difference Type": "Mismatch",
                    "Impact": "Access Policy Drift",
                    "Recommended Action": f"Align access policy '{pol_name}' for authorization server '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Authorization Servers - Access Policies",
                    "Object": name,
                    "Attribute": pol_name,
                    "Value": "Match"
                })

        for pol_name in polB_map:
            if pol_name not in polA_map:
                diffs.append({
                    "Category": "Authorization Servers - Access Policies",
                    "Object": name,
                    "Attribute": pol_name,
                    "Env A Value": "Missing",
                    "Env B Value": "Exists",
                    "Difference Type": "Extra in Env B",
                    "Impact": "Unexpected Access Policy",
                    "Recommended Action": f"Review extra access policy '{pol_name}' for authorization server '{name}' in Env B",
                    "Priority": "🟡 Low"
                })

    return diffs, matches
