import json

from scripts.extract_identity_providers import get_identity_providers

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def compare_identity_providers(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare identity providers between Env A and Env B by name.
    Only compares settings if names match.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    idpsA = get_identity_providers(baseA, envA_token, limit=limit) or []
    idpsB = get_identity_providers(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {i.get("name") or i.get("id"): i for i in idpsA}
    dictB = {i.get("name") or i.get("id"): i for i in idpsB}

    for name, idpA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Federation Access",
                "Recommended Action": f"Create identity provider '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        idpB = dictB[name]
        statusA = idpA.get("status") if isinstance(idpA, dict) else None
        statusB = idpB.get("status") if isinstance(idpB, dict) else None
        if statusA != statusB:
            diffs.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Status",
                "Env A Value": statusA or "",
                "Env B Value": statusB or "",
                "Difference Type": "Mismatch",
                "Impact": "Federation Availability",
                "Recommended Action": f"Align identity provider status for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Status",
                "Value": statusA or ""
            })

        protocolA = (idpA.get("protocol") or {}) if isinstance(idpA, dict) else {}
        protocolB = (idpB.get("protocol") or {}) if isinstance(idpB, dict) else {}
        protocol_typeA = protocolA.get("type")
        protocol_typeB = protocolB.get("type")
        if protocol_typeA != protocol_typeB:
            diffs.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Protocol Type",
                "Env A Value": protocol_typeA or "",
                "Env B Value": protocol_typeB or "",
                "Difference Type": "Mismatch",
                "Impact": "Federation Protocol",
                "Recommended Action": f"Align identity provider protocol type for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Protocol Type",
                "Value": protocol_typeA or ""
            })

        policyA = idpA.get("policy", {}) if isinstance(idpA, dict) else {}
        policyB = idpB.get("policy", {}) if isinstance(idpB, dict) else {}
        if _signature(policyA) != _signature(policyB):
            diffs.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Policy",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Federation Drift",
                "Recommended Action": f"Align identity provider policy for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "Policy",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Identity Providers",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected IdP",
                "Recommended Action": f"Review extra identity provider '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
