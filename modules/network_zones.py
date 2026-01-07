from scripts.extract_network_zones import get_network_zones

def compare_network_zones(envA_domain, envA_token, envB_domain, envB_token):
    """
    Compare Network Zones across two Okta environments.
    Returns: (diffs, matches)
    """

    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    zonesA = get_network_zones(baseA, envA_token)
    zonesB = get_network_zones(baseB, envB_token)

    diffs = []
    matches = []

    dictA = {z["name"]: z for z in zonesA}
    dictB = {z["name"]: z for z in zonesB}

    compare_fields = [
        ("type",       "Type"),
        ("gateways",   "Gateways"),
        ("proxies",    "Proxies"),
        ("locations",  "Locations"),
        ("status",     "Status")
    ]

    # ----------------------------
    # A → B comparison
    # ----------------------------
    for name, zoneA in dictA.items():
        if name not in dictB:
            diffs.append({
                "Category": "Network Zones",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Access Control",
                "Recommended Action": f"Create zone '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        zoneB = dictB[name]
        mismatch_found = False

        for key, label in compare_fields:
            valA = zoneA.get(key, "")
            valB = zoneB.get(key, "")

            if valA != valB:
                diffs.append({
                    "Category": "Network Zones",
                    "Object": name,
                    "Attribute": label,
                    "Env A Value": valA,
                    "Env B Value": valB,
                    "Difference Type": "Mismatch",
                    "Impact": "Zone Configuration Drift",
                    "Recommended Action": f"Align '{label}' in '{name}'",
                    "Priority": "🟠 Medium"
                })
                mismatch_found = True

        if not mismatch_found:
            matches.append({
                "Category": "Network Zones",
                "Object": name,
                "Attribute": "All Attributes",
                "Value": "Match"
            })

    # ----------------------------
    # Zones extra in B
    # ----------------------------
    for name, zoneB in dictB.items():
        if name not in dictA:
            diffs.append({
                "Category": "Network Zones",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Zone",
                "Recommended Action": f"Review extra zone '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
