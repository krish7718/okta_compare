import requests
from scripts.extract_applications import (
    get_applications,
    get_application_groups  
)


def _normalize_app_name(app):
    return app.get("label") or app.get("name") or app.get("id")


def _extract_group_names(groups):
    names = set()
    if not groups:
        return names
    for g in groups:
        if isinstance(g, str):
            names.add(g)
            continue
        if isinstance(g, dict):
            # common shapes: group object from Okta extractors
            profile = g.get("profile") or {}
            if isinstance(profile, dict) and profile.get("name"):
                names.add(profile.get("name"))
            elif g.get("name"):
                names.add(g.get("name"))
            elif g.get("id"):
                names.add(g.get("id"))
    return names


def _missing_app(name, missing_env):
    return {
        "Category": "Applications",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Exists" if missing_env == "Env B" else "Missing",
        "Env B Value": "Missing" if missing_env == "Env B" else "Exists",
        "Difference Type": f"Missing in {missing_env}",
        "Impact": "Access & Provisioning",
        "Recommended Action": f"Create application '{name}' in {missing_env}",
        "Priority": "🔴 Critical"
    }


def _extra_app(name, extra_env):
    return {
        "Category": "Applications",
        "Object": name,
        "Attribute": "-",
        "Env A Value": "Missing" if extra_env == "Env B" else "Exists",
        "Env B Value": "Exists" if extra_env == "Env B" else "Missing",
        "Difference Type": f"Extra in {extra_env}",
        "Impact": "Unexpected Access",
        "Recommended Action": f"Review extra application '{name}' in {extra_env}",
        "Priority": "🟡 Low"
    }


def _compare_app_group_assignments(app_name, appA, appB, baseA, tokenA, baseB, tokenB, diffs, matches):
    app_id_A = appA.get("id")
    app_id_B = appB.get("id")

    groupsA = []
    groupsB = []

    try:
        if app_id_A:
            groupsA = get_application_groups(baseA, tokenA, app_id_A) or []
    except Exception:
        groupsA = []

    try:
        if app_id_B:
            groupsB = get_application_groups(baseB, tokenB, app_id_B) or []
    except Exception:
        groupsB = []

    namesA = _extract_group_names(groupsA)
    namesB = _extract_group_names(groupsB)

    if namesA != namesB:
        diffs.append({
            "Category": "Applications",
            "Object": app_name,
            "Attribute": "Assigned Groups",
            "Env A Value": ", ".join(sorted(namesA)) if namesA else "<none>",
            "Env B Value": ", ".join(sorted(namesB)) if namesB else "<none>",
            "Difference Type": "Mismatch",
            "Impact": "Access Assignment Drift",
            "Recommended Action": f"Align group assignments for application '{app_name}' between environments",
            "Priority": "🟠 Medium"
        })
    else:
        matches.append({
            "Category": "Applications",
            "Object": app_name,
            "Attribute": "Assigned Groups",
            "Value": ", ".join(sorted(namesA))
        })

    return diffs, matches


def compare_applications(
    envA_domain,
    envA_token,
    envB_domain,
    envB_token,
    compare_group_assignments=False,
    app_limit=200,
):
    """
    Compare applications between Env A and Env B.
    Compares application names and, optionally, group assignments for matching apps.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    appsA = get_applications(baseA, envA_token, limit=app_limit) or []
    appsB = get_applications(baseB, envB_token, limit=app_limit) or []

    diffs = []
    matches = []

    dictA = {_normalize_app_name(a): a for a in appsA}
    dictB = {_normalize_app_name(b): b for b in appsB}

    # Compare A -> B
    for name, appA in dictA.items():
        if name not in dictB:
            diffs.append(_missing_app(name, "Env B"))
            continue

        appB = dictB[name]

        if compare_group_assignments:
            # Compare group assignments for matching apps
            diffs, matches = _compare_app_group_assignments(
                app_name=name,
                appA=appA,
                appB=appB,
                baseA=baseA,
                tokenA=envA_token,
                baseB=baseB,
                tokenB=envB_token,
                diffs=diffs,
                matches=matches
            )
        else:
            matches.append({
                "Category": "Applications",
                "Object": name,
                "Attribute": "Name",
                "Value": name
            })

    # Extra apps in B
    for name in dictB:
        if name not in dictA:
            diffs.append(_extra_app(name, "Env B"))

    return diffs, matches
