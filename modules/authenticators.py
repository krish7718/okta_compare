from scripts.extract_authenticators import get_authenticators


def _auth_key(auth):
    return auth.get("key") or auth.get("name") or auth.get("id")


def _summarize_authenticator(auth):
    return {
        "name": auth.get("name") or auth.get("label"),
        "key": auth.get("key"),
        "type": auth.get("type"),
        "status": auth.get("status"),
    }


def compare_authenticators(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare authenticators between Env A and Env B.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    authA = get_authenticators(baseA, envA_token, limit=limit) or []
    authB = get_authenticators(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_auth_key(a): a for a in authA}
    dictB = {_auth_key(b): b for b in authB}

    for key, a in dictA.items():
        if key not in dictB:
            diffs.append({
                "Category": "Authenticators",
                "Object": a.get("name") or key,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Authentication Coverage",
                "Recommended Action": f"Enable authenticator '{a.get('name') or key}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        b = dictB[key]
        a_summary = _summarize_authenticator(a)
        b_summary = _summarize_authenticator(b)

        for field in ("name", "type", "status"):
            if a_summary.get(field) != b_summary.get(field):
                diffs.append({
                    "Category": "Authenticators",
                    "Object": a_summary.get("name") or key,
                    "Attribute": field.title(),
                    "Env A Value": a_summary.get(field) or "",
                    "Env B Value": b_summary.get(field) or "",
                    "Difference Type": "Mismatch",
                    "Impact": "Authentication Drift",
                    "Recommended Action": f"Align authenticator {field} for '{a_summary.get('name') or key}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Authenticators",
                    "Object": a_summary.get("name") or key,
                    "Attribute": field.title(),
                    "Value": a_summary.get(field) or ""
                })

    for key, b in dictB.items():
        if key not in dictA:
            diffs.append({
                "Category": "Authenticators",
                "Object": b.get("name") or key,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Authenticator",
                "Recommended Action": f"Review extra authenticator '{b.get('name') or key}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
