import json

from scripts.extract_entity_risk_policies import get_entity_risk_policies, get_entity_risk_policy_rules

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _normalize_policy_name(policy):
    return policy.get("name") or policy.get("id")


def _compare_attrs(category, object_name, attrs, objA, objB, impact, recommendation_prefix, diffs, matches):
    for attr in attrs:
        valA = objA.get(attr, "")
        valB = objB.get(attr, "")
        if _signature(valA) != _signature(valB):
            diffs.append({
                "Category": category,
                "Object": object_name,
                "Attribute": attr,
                "Env A Value": "Different" if isinstance(valA, (dict, list)) else valA,
                "Env B Value": "Different" if isinstance(valB, (dict, list)) else valB,
                "Difference Type": "Mismatch",
                "Impact": impact,
                "Recommended Action": f"{recommendation_prefix} '{attr}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": category,
                "Object": object_name,
                "Attribute": attr,
                "Value": valA if not isinstance(valA, (dict, list)) else "Match"
            })
    return diffs, matches


def compare_entity_risk_policies(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    category = "Entity Risk Policies"
    policiesA = get_entity_risk_policies(envA_domain, envA_token, limit=limit) or []
    policiesB = get_entity_risk_policies(envB_domain, envB_token, limit=limit) or []
    diffs = []
    matches = []
    dictA = {_normalize_policy_name(policy): policy for policy in policiesA}
    dictB = {_normalize_policy_name(policy): policy for policy in policiesB}

    for name, polA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": category, "Object": name, "Attribute": "-", "Env A Value": "Exists", "Env B Value": "Missing",
                "Difference Type": "Missing in Env B", "Impact": "Risk Policy Coverage",
                "Recommended Action": f"Create entity risk policy '{name}' in Env B", "Priority": "🔴 Critical"
            })
            continue
        polB = dictB[name]
        diffs, matches = _compare_attrs(
            category, name, ["status", "priority", "description", "conditions", "settings"],
            polA, polB, "Risk Policy Drift", f"Align entity risk policy '{name}' attribute", diffs, matches
        )
        rulesA = get_entity_risk_policy_rules(envA_domain, envA_token, polA.get("id")) or []
        rulesB = get_entity_risk_policy_rules(envB_domain, envB_token, polB.get("id")) or []
        rules_dictA = {(r.get("name") or r.get("id")): r for r in rulesA}
        rules_dictB = {(r.get("name") or r.get("id")): r for r in rulesB}
        for rule_name, ruleA in rules_dictA.items():
            object_name = f"{name} / Rule: {rule_name}"
            if rule_name not in rules_dictB:
                diffs.append({
                    "Category": category, "Object": object_name, "Attribute": "-", "Env A Value": "Exists", "Env B Value": "Missing",
                    "Difference Type": "Missing in Env B", "Impact": "Risk Policy Coverage",
                    "Recommended Action": f"Create rule '{rule_name}' in entity risk policy '{name}'", "Priority": "🔴 Critical"
                })
                continue
            diffs, matches = _compare_attrs(
                category, object_name, ["priority", "status", "conditions", "actions", "settings"],
                ruleA, rules_dictB[rule_name], "Risk Policy Rule Drift",
                f"Align rule '{rule_name}' in entity risk policy '{name}' attribute", diffs, matches
            )
        for rule_name in rules_dictB:
            if rule_name not in rules_dictA:
                diffs.append({
                    "Category": category, "Object": f"{name} / Rule: {rule_name}", "Attribute": "-", "Env A Value": "Missing", "Env B Value": "Exists",
                    "Difference Type": "Extra in Env B", "Impact": "Unexpected Risk Policy Rule",
                    "Recommended Action": f"Review extra rule '{rule_name}' in entity risk policy '{name}'", "Priority": "🟡 Low"
                })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": category, "Object": name, "Attribute": "-", "Env A Value": "Missing", "Env B Value": "Exists",
                "Difference Type": "Extra in Env B", "Impact": "Unexpected Risk Policy",
                "Recommended Action": f"Review extra entity risk policy '{name}' in Env B", "Priority": "🟡 Low"
            })
    return diffs, matches
