import json

from scripts.extract_attack_protection import get_attack_protection_bundle

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _object_key(item):
    return (
        item.get("name")
        or item.get("label")
        or item.get("type")
        or item.get("id")
    )


def _compare_singleton(name, category, valA, valB, diffs, matches):
    if valA is None and valB is None:
        matches.append({
            "Category": category,
            "Object": name,
            "Attribute": "Settings",
            "Value": "Not Available"
        })
        return diffs, matches

    if valA is None or valB is None:
        diffs.append({
            "Category": category,
            "Object": name,
            "Attribute": "Settings",
            "Env A Value": "Not Available" if valA is None else "Available",
            "Env B Value": "Not Available" if valB is None else "Available",
            "Difference Type": "Mismatch",
            "Impact": "Attack Protection Drift",
            "Recommended Action": f"Ensure {name.lower()} are accessible in both environments",
            "Priority": "🟠 Medium"
        })
        return diffs, matches

    if _signature(valA) != _signature(valB):
        diffs.append({
            "Category": category,
            "Object": name,
            "Attribute": "Settings",
            "Env A Value": "Different",
            "Env B Value": "Different",
            "Difference Type": "Mismatch",
            "Impact": "Attack Protection Drift",
            "Recommended Action": f"Align {name.lower()} between environments",
            "Priority": "🟠 Medium"
        })
    else:
        matches.append({
            "Category": category,
            "Object": name,
            "Attribute": "Settings",
            "Value": "Match"
        })
    return diffs, matches


def _compare_collection(name, category, itemsA, itemsB, diffs, matches):
    dictA = {_object_key(item): item for item in itemsA or [] if _object_key(item)}
    dictB = {_object_key(item): item for item in itemsB or [] if _object_key(item)}

    for key, itemA in dictA.items():
        if key not in dictB:
            diffs.append({
                "Category": category,
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Attack Protection Coverage",
                "Recommended Action": f"Create {name[:-1].lower()} '{key}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        itemB = dictB[key]
        if _signature(itemA) != _signature(itemB):
            diffs.append({
                "Category": category,
                "Object": key,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Attack Protection Drift",
                "Recommended Action": f"Align {name[:-1].lower()} '{key}' between environments",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": category,
                "Object": key,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for key in dictB:
        if key not in dictA:
            diffs.append({
                "Category": category,
                "Object": key,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Attack Protection Object",
                "Recommended Action": f"Review extra {name[:-1].lower()} '{key}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches


def compare_attack_protection(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare dedicated attack protection configuration across both environments.
    Returns (diffs, matches).
    """
    bundleA = get_attack_protection_bundle(envA_domain, envA_token, limit=limit) or {}
    bundleB = get_attack_protection_bundle(envB_domain, envB_token, limit=limit) or {}

    diffs = []
    matches = []
    category = "Access Controls - Attack Protection"

    singleton_checks = [
        ("Authenticator Settings", "authenticator_settings"),
        ("User Lockout Settings", "user_lockout_settings"),
        ("Bot Protection Configuration", "bot_protection_configuration"),
        ("Org-wide CAPTCHA Settings", "org_captcha_settings"),
    ]

    for label, key in singleton_checks:
        diffs, matches = _compare_singleton(
            label,
            category,
            bundleA.get(key),
            bundleB.get(key),
            diffs,
            matches,
        )

    diffs, matches = _compare_collection(
        "Behavior Detection Rules",
        category,
        bundleA.get("behavior_detection_rules"),
        bundleB.get("behavior_detection_rules"),
        diffs,
        matches,
    )
    diffs, matches = _compare_collection(
        "CAPTCHAs",
        category,
        bundleA.get("captchas"),
        bundleB.get("captchas"),
        diffs,
        matches,
    )

    return diffs, matches
