import json

from scripts.extract_profile_mappings import (
    get_idp_app_user_types,
    get_profile_mappings,
    get_profile_mapping_by_id,
)

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _mapping_signature(mapping_detail):
    normalized = []
    payload = mapping_detail or {}
    properties = payload.get("properties") or {}
    for target_field, rule in properties.items():
        if isinstance(rule, dict):
            normalized.append({
                "targetField": target_field,
                "sourceExpression": rule.get("expression") or rule.get("sourceExpression"),
                "pushStatus": rule.get("pushStatus"),
            })

    prop_mappings = payload.get("propertyMappings") or []
    for entry in prop_mappings:
        if isinstance(entry, dict):
            normalized.append({
                "targetField": entry.get("targetField"),
                "sourceExpression": entry.get("sourceExpression") or entry.get("expression"),
                "pushStatus": entry.get("pushStatus"),
            })

    return _signature(sorted(normalized, key=lambda x: (x.get("targetField") or "", x.get("sourceExpression") or "")))


def compare_profile_mappings(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare profile mappings for Directories or Identity Providers only.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    idp_types_a = get_idp_app_user_types(baseA, envA_token) or []
    idp_types_b = get_idp_app_user_types(baseB, envB_token) or []
    idp_names_a = {t.get("name") for t in idp_types_a if t.get("name")}
    idp_names_b = {t.get("name") for t in idp_types_b if t.get("name")}

    diffs = []
    matches = []

    mappingsA = get_profile_mappings(baseA, envA_token) or []
    mappingsB = get_profile_mappings(baseB, envB_token) or []

    def _mapping_key(mapping):
        source = mapping.get("source") or {}
        target = mapping.get("target") or {}
        source_name = source.get("name")
        target_name = target.get("name")
        return f"{source_name} -> {target_name}"

    def _is_idp_mapping(mapping, idp_names):
        source = mapping.get("source") or {}
        target = mapping.get("target") or {}
        return (source.get("name") in idp_names) or (target.get("name") in idp_names)

    dictA = {_mapping_key(m): m for m in mappingsA if _is_idp_mapping(m, idp_names_a)}
    dictB = {_mapping_key(m): m for m in mappingsB if _is_idp_mapping(m, idp_names_b)}

    for key, mapA in dictA.items():
        if key not in dictB:
            diffs.append({
                "Category": "Profile Mappings",
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Profile Mapping",
                "Recommended Action": f"Create mapping '{key}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        mapB = dictB[key]
        detailA = get_profile_mapping_by_id(baseA, envA_token, mapA.get("id"))
        detailB = get_profile_mapping_by_id(baseB, envB_token, mapB.get("id"))
        if not detailA or not detailB:
            diffs.append({
                "Category": "Profile Mappings",
                "Object": key,
                "Attribute": "Settings",
                "Env A Value": "Unavailable",
                "Env B Value": "Unavailable",
                "Difference Type": "Mismatch",
                "Impact": "Profile Mapping Drift",
                "Recommended Action": f"Verify mapping details for '{key}'",
                "Priority": "🟠 Medium"
            })
            continue

        if _mapping_signature(detailA) != _mapping_signature(detailB):
            diffs.append({
                "Category": "Profile Mappings",
                "Object": key,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Profile Mapping Drift",
                "Recommended Action": f"Align mapping '{key}' between environments",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Profile Mappings",
                "Object": key,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for key in dictB:
        if key not in dictA:
            diffs.append({
                "Category": "Profile Mappings",
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Profile Mapping",
                "Recommended Action": f"Review extra mapping '{key}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
