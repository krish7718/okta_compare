import json

from scripts.extract_profile_enrollment_policies import (
    get_profile_enrollment_policies,
    get_profile_enrollment_policy_rules,
)

_SKIP_KEYS = {"id", "_links", "links", "created", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _normalize_policy_name(policy):
    return policy.get("name") or policy.get("id")


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _missing_policy(name, missing_env):
    return {
        "Category": "Profile Enrollment Policies",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Exists" if missing_env == "Env B" else "Missing",
        "Env B Value": "Missing" if missing_env == "Env B" else "Exists",
        "Difference Type": f"Missing in {missing_env}",
        "Impact": "User Enrollment",
        "Recommended Action": f"Create profile enrollment policy '{name}' in {missing_env}",
        "Priority": "🔴 Critical"
    }


def _extra_policy(name, extra_env):
    return {
        "Category": "Profile Enrollment Policies",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Missing" if extra_env == "Env B" else "Exists",
        "Env B Value": "Exists" if extra_env == "Env B" else "Missing",
        "Difference Type": f"Extra in {extra_env}",
        "Impact": "Unexpected Policy",
        "Recommended Action": f"Review extra profile enrollment policy '{name}' in {extra_env}",
        "Priority": "🟡 Low"
    }


def _compare_policy_attributes(name, polA, polB, diffs, matches):
    attrs = ["status", "priority", "description", "conditions", "settings"]

    for attr in attrs:
        valA = polA.get(attr, "")
        valB = polB.get(attr, "")

        if _signature(valA) != _signature(valB):
            diffs.append({
                "Category": "Profile Enrollment Policies",
                "Object": name,
                "Attribute": attr,
                "Env A Value": "Different" if isinstance(valA, (dict, list)) else valA,
                "Env B Value": "Different" if isinstance(valB, (dict, list)) else valB,
                "Difference Type": "Mismatch",
                "Impact": "Enrollment Drift",
                "Recommended Action": f"Align profile enrollment policy '{name}' attribute '{attr}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Profile Enrollment Policies",
                "Object": name,
                "Attribute": attr,
                "Value": valA if not isinstance(valA, (dict, list)) else "Match"
            })

    return diffs, matches


def _compare_rule_attributes(policy_name, rule_name, ruleA, ruleB, diffs, matches):
    attrs = ["priority", "status", "conditions", "actions", "settings"]

    for attr in attrs:
        valA = ruleA.get(attr, "")
        valB = ruleB.get(attr, "")

        if _signature(valA) != _signature(valB):
            diffs.append({
                "Category": "Profile Enrollment Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": attr,
                "Env A Value": "Different" if isinstance(valA, (dict, list)) else valA,
                "Env B Value": "Different" if isinstance(valB, (dict, list)) else valB,
                "Difference Type": "Mismatch",
                "Impact": "Enrollment Rule Drift",
                "Recommended Action": f"Align rule '{rule_name}' in profile enrollment policy '{policy_name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Profile Enrollment Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": attr,
                "Value": valA if not isinstance(valA, (dict, list)) else "Match"
            })

    return diffs, matches


def _compare_policy_rules(policy_name, rulesA, rulesB, diffs, matches):
    dictA = {(rule.get("name") or rule.get("id")): rule for rule in rulesA or []}
    dictB = {(rule.get("name") or rule.get("id")): rule for rule in rulesB or []}

    for rule_name, ruleA in dictA.items():
        if rule_name not in dictB:
            diffs.append({
                "Category": "Profile Enrollment Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "User Enrollment",
                "Recommended Action": f"Create rule '{rule_name}' in profile enrollment policy '{policy_name}'",
                "Priority": "🔴 Critical"
            })
            continue

        diffs, matches = _compare_rule_attributes(
            policy_name,
            rule_name,
            ruleA,
            dictB[rule_name],
            diffs,
            matches,
        )

    for rule_name in dictB:
        if rule_name not in dictA:
            diffs.append({
                "Category": "Profile Enrollment Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Rule",
                "Recommended Action": f"Review extra rule '{rule_name}' in profile enrollment policy '{policy_name}'",
                "Priority": "🟡 Low"
            })

    return diffs, matches


def compare_profile_enrollment_policies(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare profile enrollment policies and every rule/settings under each policy.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    policiesA = get_profile_enrollment_policies(baseA, envA_token, limit=limit) or []
    policiesB = get_profile_enrollment_policies(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_normalize_policy_name(policy): policy for policy in policiesA}
    dictB = {_normalize_policy_name(policy): policy for policy in policiesB}

    for name, polA in dictA.items():
        if name not in dictB:
            diffs.append(_missing_policy(name, "Env B"))
            continue

        polB = dictB[name]
        diffs, matches = _compare_policy_attributes(name, polA, polB, diffs, matches)

        rulesA = get_profile_enrollment_policy_rules(baseA, envA_token, polA.get("id")) or []
        rulesB = get_profile_enrollment_policy_rules(baseB, envB_token, polB.get("id")) or []
        diffs, matches = _compare_policy_rules(name, rulesA, rulesB, diffs, matches)

    for name in dictB:
        if name not in dictA:
            diffs.append(_extra_policy(name, "Env B"))

    return diffs, matches
