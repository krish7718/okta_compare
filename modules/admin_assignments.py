from scripts.extract_admin_roles import get_admin_users, get_admin_groups, get_admin_apps


def _admin_identity(admin):
    if isinstance(admin, dict):
        return admin.get("login") or admin.get("email") or admin.get("displayName") or admin.get("userId")
    return str(admin)


def _sorted_set(values):
    return sorted({v for v in values if v})


def compare_admin_assignments(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare admin assignments between Env A and Env B.
    Returns (diffs, matches).
    """
    diffs = []
    matches = []
    adminsA = get_admin_users(envA_domain, envA_token) or []
    adminsB = get_admin_users(envB_domain, envB_token) or []

    namesA = _sorted_set(_admin_identity(a) for a in adminsA)
    namesB = _sorted_set(_admin_identity(a) for a in adminsB)

    if namesA != namesB:
        diffs.append({
            "Category": "Admin Assignments",
            "Object": "Admin Users",
            "Attribute": "Users",
            "Env A Value": ", ".join(namesA) if namesA else "<none>",
            "Env B Value": ", ".join(namesB) if namesB else "<none>",
            "Difference Type": "Mismatch",
            "Impact": "Admin Assignment Drift",
            "Recommended Action": "Align admin users between environments",
            "Priority": "🟠 Medium"
        })
    else:
        matches.append({
            "Category": "Admin Assignments",
            "Object": "Admin Users",
            "Attribute": "Users",
            "Value": ", ".join(namesA) if namesA else "<none>"
        })

    groupsA = get_admin_groups(envA_domain, envA_token) or []
    groupsB = get_admin_groups(envB_domain, envB_token) or []
    group_namesA = _sorted_set(g.get("name") or g.get("groupId") for g in groupsA)
    group_namesB = _sorted_set(g.get("name") or g.get("groupId") for g in groupsB)

    if group_namesA != group_namesB:
        diffs.append({
            "Category": "Admin Assignments",
            "Object": "Admin Groups",
            "Attribute": "Groups",
            "Env A Value": ", ".join(group_namesA) if group_namesA else "<none>",
            "Env B Value": ", ".join(group_namesB) if group_namesB else "<none>",
            "Difference Type": "Mismatch",
            "Impact": "Admin Group Assignment Drift",
            "Recommended Action": "Align admin groups between environments",
            "Priority": "🟠 Medium"
        })
    else:
        matches.append({
            "Category": "Admin Assignments",
            "Object": "Admin Groups",
            "Attribute": "Groups",
            "Value": ", ".join(group_namesA) if group_namesA else "<none>"
        })

    appsA = get_admin_apps(envA_domain, envA_token) or []
    appsB = get_admin_apps(envB_domain, envB_token) or []
    app_namesA = _sorted_set(a.get("displayName") or a.get("appInstanceId") for a in appsA)
    app_namesB = _sorted_set(a.get("displayName") or a.get("appInstanceId") for a in appsB)

    if app_namesA != app_namesB:
        diffs.append({
            "Category": "Admin Assignments",
            "Object": "Admin Apps",
            "Attribute": "Apps",
            "Env A Value": ", ".join(app_namesA) if app_namesA else "<none>",
            "Env B Value": ", ".join(app_namesB) if app_namesB else "<none>",
            "Difference Type": "Mismatch",
            "Impact": "Admin App Assignment Drift",
            "Recommended Action": "Align admin app assignments between environments",
            "Priority": "🟠 Medium"
        })
    else:
        matches.append({
            "Category": "Admin Assignments",
            "Object": "Admin Apps",
            "Attribute": "Apps",
            "Value": ", ".join(app_namesA) if app_namesA else "<none>"
        })

    return diffs, matches
