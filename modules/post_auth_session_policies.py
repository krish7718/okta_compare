import json

from scripts.extract_post_auth_session_policies import (
    get_post_auth_session_policies,
    get_post_auth_session_policy_rules,
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


def compare_post_auth_session_policies(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    category = "Identity Threat Protection Policies"
    policiesA = get_post_auth_session_policies(envA_domain, envA_token, limit=limit) or []
    policiesB = get_post_auth_session_policies(envB_domain, envB_token, limit=limit) or []
    diffs = []
    matches = []
    dictA = {_normalize_policy_name(policy): policy for policy in policiesA}
    dictB = {_normalize_policy_name(policy): policy for policy in policiesB}

    for name, polA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": category, "Object": name, "Attribute": "-", "Env A Value": "Exists", "Env B Value": "Missing",
                "Difference Type": "Missing in Env B", "Impact": "Identity Threat Protection Coverage",
                "Recommended Action": f"Create identity threat protection policy '{name}' in Env B", "Priority": "🔴 Critical"
            })
            continue
        polB = dictB[name]
        diffs, matches = _compare_attrs(
            category, name, ["status", "priority", "description", "conditions", "settings"],
            polA, polB, "Identity Threat Protection Drift", f"Align identity threat protection policy '{name}' attribute", diffs, matches
        )
        rulesA = get_post_auth_session_policy_rules(envA_domain, envA_token, polA.get("id")) or []
        rulesB = get_post_auth_session_policy_rules(envB_domain, envB_token, polB.get("id")) or []
        dictRulesA = {(r.get("name") or r.get("id")): r for r in rulesA}
        dictRulesB = {(r.get("name") or r.get("id")): r for r in rulesB}
        for rule_name, ruleA in dictRulesA.items():
            object_name = f"{name} / Rule: {rule_name}"
            if rule_name not in dictRulesB:
                diffs.append({
                    "Category": category, "Object": object_name, "Attribute": "-", "Env A Value": "Exists", "Env B Value": "Missing",
                    "Difference Type": "Missing in Env B", "Impact": "Identity Threat Protection Coverage",
                    "Recommended Action": f"Create rule '{rule_name}' in identity threat protection policy '{name}'", "Priority": "🔴 Critical"
                })
                continue
            diffs, matches = _compare_attrs(
                category, object_name, ["priority", "status", "conditions", "actions", "settings"],
                ruleA, dictRulesB[rule_name], "Identity Threat Protection Rule Drift",
                f"Align rule '{rule_name}' in identity threat protection policy '{name}' attribute", diffs, matches
            )
        for rule_name in dictRulesB:
            if rule_name not in dictRulesA:
                diffs.append({
                    "Category": category, "Object": f"{name} / Rule: {rule_name}", "Attribute": "-", "Env A Value": "Missing", "Env B Value": "Exists",
                    "Difference Type": "Extra in Env B", "Impact": "Unexpected Identity Threat Protection Rule",
                    "Recommended Action": f"Review extra rule '{rule_name}' in identity threat protection policy '{name}'", "Priority": "🟡 Low"
                })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": category, "Object": name, "Attribute": "-", "Env A Value": "Missing", "Env B Value": "Exists",
                "Difference Type": "Extra in Env B", "Impact": "Unexpected Identity Threat Protection Policy",
                "Recommended Action": f"Review extra identity threat protection policy '{name}' in Env B", "Priority": "🟡 Low"
            })
    return diffs, matches
