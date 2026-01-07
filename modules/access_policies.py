import json

from scripts.extract_access_policies import get_access_policies, get_access_policy_rules


def _normalize_policy_name(policy):
    return policy.get("name") or policy.get("id")


def _normalize_rules(rules):
    normalized = []
    for rule in rules or []:
        normalized.append({
            "name": rule.get("name"),
            "status": rule.get("status"),
            "priority": rule.get("priority"),
            "conditions": rule.get("conditions"),
            "actions": rule.get("actions"),
        })
    normalized.sort(key=lambda r: (r.get("priority") or 0, r.get("name") or ""))
    return normalized


def _rules_signature(rules):
    return json.dumps(_normalize_rules(rules), sort_keys=True, default=str)


def compare_access_policies(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare app sign-on access policies between Env A and Env B.
    If rules differ, mark the policy as different without rule-level detail.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    policiesA = get_access_policies(baseA, envA_token, limit=limit) or []
    policiesB = get_access_policies(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_normalize_policy_name(p): p for p in policiesA}
    dictB = {_normalize_policy_name(p): p for p in policiesB}

    for name, polA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "App Sign-On Policies",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "App Access",
                "Recommended Action": f"Create app sign-on policy '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        polB = dictB[name]
        rulesA = get_access_policy_rules(baseA, envA_token, polA.get("id"))
        rulesB = get_access_policy_rules(baseB, envB_token, polB.get("id"))

        if _rules_signature(rulesA) != _rules_signature(rulesB):
            diffs.append({
                "Category": "App Sign-On Policies",
                "Object": name,
                "Attribute": "Rules",
                "Env A Value": "Different",
                "Env B Value": "Different",
                "Difference Type": "Mismatch",
                "Impact": "Access Policy Drift",
                "Recommended Action": f"Align access policy rules for '{name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "App Sign-On Policies",
                "Object": name,
                "Attribute": "Rules",
                "Value": "Match"
            })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "App Sign-On Policies",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Policy",
                "Recommended Action": f"Review extra app sign-on policy '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
