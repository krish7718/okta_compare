import requests
from scripts.extract_group_rules import (
    get_groups_map,
    get_group_rules
)


def compare_group_rules(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compare group rules between Env A and Env B.
    Returns: (diffs, matches)
    """

    # ---------------------------
    # Fetch required data
    # ---------------------------
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    # Maps convert groupId → groupName inside expressions
    mapA = get_groups_map(baseA, envA_token)
    mapB = get_groups_map(baseB, envB_token)

    # Raw group rules
    rulesA = get_group_rules(baseA, envA_token)
    rulesB = get_group_rules(baseB, envB_token)

    diffs = []
    matches = []

    # Convert rule sets into comparable dictionaries
    dictA = {r["name"]: r for r in rulesA}
    dictB = {r["name"]: r for r in rulesB}

    # ---------------------------
    # Compare A → B
    # ---------------------------
    for name, ruleA in dictA.items():

        condA = ruleA.get("conditions", {}).get("expression", {}).get("value", "")
        condA = _replace_group_ids(condA, mapA)

        if name not in dictB:
            # Missing in B
            diffs.append({
                "Category": "Group Rules",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Group Assignment",
                "Recommended Action": f"Create rule '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
        else:
            ruleB = dictB[name]
            condB = ruleB.get("conditions", {}).get("expression", {}).get("value", "")
            condB = _replace_group_ids(condB, mapB)

            # Mismatch
            if condA != condB:
                diffs.append({
                    "Category": "Group Rules",
                    "Object": name,
                    "Attribute": "Condition",
                    "Env A Value": condA,
                    "Env B Value": condB,
                    "Difference Type": "Mismatch",
                    "Impact": "Assignment Drift",
                    "Recommended Action": f"Align condition for rule '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                # Perfect match
                matches.append({
                    "Category": "Group Rules",
                    "Object": name,
                    "Attribute": "Condition",
                    "Value": condA
                })

    # ---------------------------
    # Extra rules in B
    # ---------------------------
    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Group Rules",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Assignment",
                "Recommended Action": f"Review extra rule '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches


# ---------------------------------------------------
# Helper: Replace group IDs with friendly group names
# ---------------------------------------------------
def _replace_group_ids(expression, groups_map):
    """
    Replaces groupIds inside expression string with actual group names.
    Example: 'String.contains(user.login,"00g123")' → 'String.contains(user.login,"Finance Users")'
    """
    if not expression:
        return expression

    for gid, gname in groups_map.items():
        expression = expression.replace(gid, gname)

    return expression
