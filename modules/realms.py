import json

from scripts.extract_realms import get_realms, get_realm_assignments

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _realm_name(realm):
    return (
        realm.get("name")
        or realm.get("label")
        or realm.get("displayName")
        or realm.get("realmName")
        or realm.get("id")
    )


def compare_realms(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare realms between Env A and Env B by name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    realmsA = get_realms(baseA, envA_token, limit=limit) or []
    realmsB = get_realms(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_realm_name(r): r for r in realmsA}
    dictB = {_realm_name(r): r for r in realmsB}

    for name, realmA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Realms",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Realm Access",
                "Recommended Action": f"Create realm '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        realmB = dictB[name]
        if _signature(realmA) != _signature(realmB):
            diffs.append({
                "Category": "Realms",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Realm Drift",
                "Recommended Action": f"Align realm settings for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Realms",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Realms",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Realm",
                "Recommended Action": f"Review extra realm '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches


def _assignment_name(assignment):
    return (
        assignment.get("name")
        or assignment.get("label")
        or assignment.get("displayName")
        or assignment.get("id")
    )


def _assignment_signature(assignment):
    payload = {
        "status": assignment.get("status"),
        "conditions": assignment.get("conditions"),
        "actions": assignment.get("actions"),
        "domains": assignment.get("domains"),
        "isDefault": assignment.get("isDefault"),
        "priority": assignment.get("priority"),
    }
    return json.dumps(_sanitize(payload), sort_keys=True, default=str)


def compare_realm_assignments(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare realm assignments between Env A and Env B by assignment name.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    assignmentsA = get_realm_assignments(baseA, envA_token, limit=limit) or []
    assignmentsB = get_realm_assignments(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_assignment_name(a): a for a in assignmentsA}
    dictB = {_assignment_name(a): a for a in assignmentsB}

    for name, assignA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Realm Assignments",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Realm Assignment Drift",
                "Recommended Action": f"Create realm assignment '{name}' in Env B",
                "Priority": "🟠 Medium"
            })
            continue

        assignB = dictB[name]
        if _assignment_signature(assignA) != _assignment_signature(assignB):
            diffs.append({
                "Category": "Realm Assignments",
                "Object": name,
                "Attribute": "Settings",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Realm Assignment Drift",
                "Recommended Action": f"Align realm assignment '{name}' between environments",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Realm Assignments",
                "Object": name,
                "Attribute": "Settings",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Realm Assignments",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Realm Assignment Drift",
                "Recommended Action": f"Review extra realm assignment '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
