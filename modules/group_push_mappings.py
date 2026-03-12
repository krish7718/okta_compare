import json

from scripts.extract_group_push_mappings import get_group_push_mappings

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _app_label(mapping):
    app = mapping.get("_app") or {}
    label = app.get("label") or app.get("name") or app.get("id") or "Unknown App"
    app_type = app.get("name") or app.get("signOnMode") or "unknown"
    return f"{label} ({app_type})"


def _mapping_key(mapping):
    source = (
        mapping.get("sourceGroupName")
        or mapping.get("sourceGroup")
        or mapping.get("sourceGroupId")
        or mapping.get("id")
    )
    target = (
        mapping.get("targetGroupName")
        or mapping.get("targetGroup")
        or mapping.get("targetGroupId")
        or mapping.get("id")
    )
    return f"{_app_label(mapping)} / {source} -> {target}"


def compare_group_push_mappings(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare group push mappings between environments.
    Returns (diffs, matches).
    """
    mappingsA = get_group_push_mappings(envA_domain, envA_token, limit=limit) or []
    mappingsB = get_group_push_mappings(envB_domain, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_mapping_key(mapping): mapping for mapping in mappingsA}
    dictB = {_mapping_key(mapping): mapping for mapping in mappingsB}

    for key, mappingA in dictA.items():
        if key not in dictB:
            diffs.append({
                "Category": "Group Push Mappings",
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Group Provisioning",
                "Recommended Action": f"Create group push mapping '{key}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        mappingB = dictB[key]
        if _signature(mappingA) != _signature(mappingB):
            diffs.append({
                "Category": "Group Push Mappings",
                "Object": key,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Group Push Drift",
                "Recommended Action": f"Align group push mapping settings for '{key}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Group Push Mappings",
                "Object": key,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for key in dictB:
        if key not in dictA:
            diffs.append({
                "Category": "Group Push Mappings",
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Group Push Mapping",
                "Recommended Action": f"Review extra group push mapping '{key}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
