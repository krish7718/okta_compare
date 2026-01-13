import json

from scripts.extract_profile_schema import get_user_type_id, get_user_profile_schemas

_SKIP_KEYS = {"id", "_links", "links"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _collect_properties(schemas):
    properties = {}
    for schema in schemas or []:
        schema_props = (schema.get("schema") or {}).get("properties") or {}
        for name, settings in schema_props.items():
            properties[name] = settings
    return properties


def compare_user_profile_schema(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compare profile attribute schema for profile 'user'.
    Returns (diffs, matches).
    """
    user_type_id_a = get_user_type_id(envA_domain, envA_token)
    user_type_id_b = get_user_type_id(envB_domain, envB_token)

    if not user_type_id_a or not user_type_id_b:
        return [], []

    schemasA = get_user_profile_schemas(envA_domain, envA_token, user_type_id_a)
    schemasB = get_user_profile_schemas(envB_domain, envB_token, user_type_id_b)

    propsA = _collect_properties(schemasA)
    propsB = _collect_properties(schemasB)

    diffs = []
    matches = []

    for name, attrA in propsA.items():
        if name not in propsB:
            diffs.append({
                "Category": "Profile Schema - User",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Profile Schema",
                "Recommended Action": f"Create attribute '{name}' in Env B user schema",
                "Priority": "🔴 Critical"
            })
            continue

        attrB = propsB[name]
        if _signature(attrA) != _signature(attrB):
            diffs.append({
                "Category": "Profile Schema - User",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Profile Schema Drift",
                "Recommended Action": f"Align attribute settings for '{name}' in user schema",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Profile Schema - User",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in propsB:
        if name not in propsA:
            diffs.append({
                "Category": "Profile Schema - User",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Profile Schema",
                "Recommended Action": f"Review extra attribute '{name}' in Env B user schema",
                "Priority": "🟡 Low"
            })

    return diffs, matches
