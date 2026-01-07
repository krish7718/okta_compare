import requests
from scripts.extract_session_policies import (
    get_session_policies,
    get_policy_rules
)

# -----------------------------------------------------------
# High-level compare dispatcher
# -----------------------------------------------------------
def compare_session_policies(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compares:
      1. Global Session Policies (type=OKTA_SIGN_ON)
      2. The Rules attached to each policy

    Returns (diffs, matches) in unified format.
    """

    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    policiesA = get_session_policies(baseA, envA_token)
    policiesB = get_session_policies(baseB, envB_token)

    diffs = []
    matches = []

    dictA = {p["name"]: p for p in policiesA}
    dictB = {p["name"]: p for p in policiesB}

    # -------------------------------------------------------
    # Compare Policy Existence & Settings
    # -------------------------------------------------------
    for name, polA in dictA.items():

        if name not in dictB:
            diffs.append(_missing_policy(name, "Env B"))
            continue

        polB = dictB[name]

        # Compare top-level policy attributes
        diffs, matches = _compare_policy_attributes(name, polA, polB, diffs, matches)

        # ---------------------------------------------------
        # Compare Rules under the policy
        # ---------------------------------------------------
        rulesA = get_policy_rules(baseA, envA_token, polA["id"])
        rulesB = get_policy_rules(baseB, envB_token, polB["id"])

        diffs, matches = _compare_policy_rules(
            policy_name=name,
            rulesA=rulesA,
            rulesB=rulesB,
            diffs=diffs,
            matches=matches
        )

    # -------------------------------------------------------
    # Extra Policies in Env B
    # -------------------------------------------------------
    for name in dictB:
        if name not in dictA:
            diffs.append(_extra_policy(name, "Env B"))

    return diffs, matches



# =====================================================================
# POLICY-LEVEL HELPERS
# =====================================================================

def _missing_policy(name, missing_env):
    return {
        "Category": "Global Session Policies",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Exists" if missing_env == "Env B" else "Missing",
        "Env B Value": "Missing" if missing_env == "Env B" else "Exists",
        "Difference Type": f"Missing in {missing_env}",
        "Impact": "Authentication & Security Controls",
        "Recommended Action": f"Create policy '{name}' in {missing_env}",
        "Priority": "🔴 Critical"
    }


def _extra_policy(name, extra_env):
    return {
        "Category": "Global Session Policies",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Missing" if extra_env == "Env B" else "Exists",
        "Env B Value": "Exists" if extra_env == "Env B" else "Missing",
        "Difference Type": f"Extra in {extra_env}",
        "Impact": "Unexpected Authentication Behavior",
        "Recommended Action": f"Review extra policy '{name}' in {extra_env}",
        "Priority": "🟡 Low"
    }


def _compare_policy_attributes(name, polA, polB, diffs, matches):
    attrs = ["status", "priority", "description"]

    for attr in attrs:
        valA = polA.get(attr, "")
        valB = polB.get(attr, "")

        if valA != valB:
            diffs.append({
                "Category": "Global Session Policies",
                "Object": name,
                "Attribute": attr,
                "Env A Value": valA,
                "Env B Value": valB,
                "Difference Type": "Mismatch",
                "Impact": "Authentication Policy Drift",
                "Recommended Action": f"Align policy '{name}' attribute '{attr}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Global Session Policies",
                "Object": name,
                "Attribute": attr,
                "Value": valA
            })

    return diffs, matches



# =====================================================================
# RULE-LEVEL HELPERS
# =====================================================================

def _compare_policy_rules(policy_name, rulesA, rulesB, diffs, matches):

    dictA = {r["name"]: r for r in rulesA}
    dictB = {r["name"]: r for r in rulesB}

    for name, rA in dictA.items():

        full_obj_name = f"{policy_name} / Rule: {name}"

        if name not in dictB:
            diffs.append({
                "Category": "Global Session Policies",
                "Object": full_obj_name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Authentication Flow",
                "Recommended Action": f"Create rule '{name}' in policy '{policy_name}'",
                "Priority": "🔴 Critical"
            })
            continue

        rB = dictB[name]

        # compare rule-level fields
        diffs, matches = _compare_rule_attributes(policy_name, name, rA, rB, diffs, matches)

    # Extra rules in B
    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Global Session Policies",
                "Object": f"{policy_name} / Rule: {name}",
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Authentication Logic",
                "Recommended Action": f"Review extra rule '{name}' in policy '{policy_name}'",
                "Priority": "🟡 Low"
            })

    return diffs, matches



def _compare_rule_attributes(policy_name, rule_name, rA, rB, diffs, matches):

    attrs = ["priority", "status"]

    for attr in attrs:
        valA = rA.get(attr, "")
        valB = rB.get(attr, "")

        if valA != valB:
            diffs.append({
                "Category": "Global Session Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": attr,
                "Env A Value": valA,
                "Env B Value": valB,
                "Difference Type": "Mismatch",
                "Impact": "Rule Behavior",
                "Recommended Action": f"Align rule '{rule_name}' in policy '{policy_name}'",
                "Priority": "🟠 Medium"
            })
        else:
            matches.append({
                "Category": "Global Session Policies",
                "Object": f"{policy_name} / Rule: {rule_name}",
                "Attribute": attr,
                "Value": valA
            })

    return diffs, matches
