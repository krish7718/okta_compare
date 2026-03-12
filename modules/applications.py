import requests
from scripts.extract_applications import (
    get_applications,
    get_application_groups,
    get_application_features,
)


def _normalize_app_name(app):
    return app.get("label") or app.get("name") or app.get("id")


def _app_type(app):
    return app.get("name") or app.get("signOnMode") or "unknown"


def _app_key(app):
    return (_normalize_app_name(app), _app_type(app))


def _app_display_name(app):
    name = _normalize_app_name(app)
    app_type = _app_type(app)
    return f"{name} ({app_type})"


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


def _is_profile_source(base, token, app_id, cache):
    if not app_id:
        return False
    if app_id in cache:
        return cache[app_id]

    features = get_application_features(base, token, app_id) or []
    enabled = any(
        (feature.get("name") == "PROFILE_MASTERING")
        and str(feature.get("status") or "").upper() == "ENABLED"
        for feature in features
        if isinstance(feature, dict)
    )
    cache[app_id] = enabled
    return enabled


def _compare_profile_source_status(app_name, appA, appB, baseA, tokenA, baseB, tokenB, diffs, matches, cacheA, cacheB):
    is_source_a = _is_profile_source(baseA, tokenA, appA.get("id"), cacheA)
    is_source_b = _is_profile_source(baseB, tokenB, appB.get("id"), cacheB)

    if is_source_a != is_source_b:
        diffs.append({
            "Category": "Applications",
            "Object": app_name,
            "Attribute": "Profile Source",
            "Env A Value": "Enabled" if is_source_a else "Disabled",
            "Env B Value": "Enabled" if is_source_b else "Disabled",
            "Difference Type": "Mismatch",
            "Impact": "Profile Mastering Drift",
            "Recommended Action": f"Align profile source configuration for application '{app_name}' between environments",
            "Priority": "🟠 Medium"
        })
    elif is_source_a:
        matches.append({
            "Category": "Applications",
            "Object": app_name,
            "Attribute": "Profile Source",
            "Value": "Enabled"
        })

    return diffs, matches


def _missing_app(label, missing_env):
    return {
        "Category": "Applications",
        "Object": label,
        "Attribute": "-",
        "Env A Value": "Exists" if missing_env == "Env B" else "Missing",
        "Env B Value": "Missing" if missing_env == "Env B" else "Exists",
        "Difference Type": f"Missing in {missing_env}",
        "Impact": "Access & Provisioning",
        "Recommended Action": f"Create application '{label}' in {missing_env}",
        "Priority": "🔴 Critical"
    }


def _extra_app(label, extra_env):
    return {
        "Category": "Applications",
        "Object": label,
        "Attribute": "-",
        "Env A Value": "Missing" if extra_env == "Env B" else "Exists",
        "Env B Value": "Exists" if extra_env == "Env B" else "Missing",
        "Difference Type": f"Extra in {extra_env}",
        "Impact": "Unexpected Access",
        "Recommended Action": f"Review extra application '{label}' in {extra_env}",
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
    profile_source_cache_a = {}
    profile_source_cache_b = {}

    dictA = {_app_key(a): a for a in appsA}
    dictB = {_app_key(b): b for b in appsB}

    # Compare A -> B
    for key, appA in dictA.items():
        label = _app_display_name(appA)
        if key not in dictB:
            diffs.append(_missing_app(label, "Env B"))
            continue

        appB = dictB[key]

        diffs, matches = _compare_profile_source_status(
            app_name=label,
            appA=appA,
            appB=appB,
            baseA=baseA,
            tokenA=envA_token,
            baseB=baseB,
            tokenB=envB_token,
            diffs=diffs,
            matches=matches,
            cacheA=profile_source_cache_a,
            cacheB=profile_source_cache_b,
        )

        if compare_group_assignments:
            # Compare group assignments for matching apps
            diffs, matches = _compare_app_group_assignments(
                app_name=label,
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
                "Object": label,
                "Attribute": "Name / Type",
                "Value": label
            })

    # Extra apps in B
    for key, appB in dictB.items():
        if key not in dictA:
            diffs.append(_extra_app(_app_display_name(appB), "Env B"))

    return diffs, matches
