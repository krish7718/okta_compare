import json

from scripts.extract_event_hooks import get_event_hooks

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _event_hook_key(hook):
    return hook.get("name") or hook.get("id")


def compare_event_hooks(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare event hooks between Env A and Env B by name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    hooksA = get_event_hooks(baseA, envA_token, limit=limit) or []
    hooksB = get_event_hooks(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_event_hook_key(h): h for h in hooksA}
    dictB = {_event_hook_key(h): h for h in hooksB}

    for name, hookA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Event Hooks",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Event Delivery",
                "Recommended Action": f"Create event hook '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        hookB = dictB[name]
        if _signature(hookA) != _signature(hookB):
            diffs.append({
                "Category": "Event Hooks",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Event Hook Drift",
                "Recommended Action": f"Align event hook settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Event Hooks",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Event Hooks",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Event Hook",
                "Recommended Action": f"Review extra event hook '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
