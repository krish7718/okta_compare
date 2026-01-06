import requests
import pandas as pd
import io
import csv
from flask import Flask, session, request, render_template, send_file
from datetime import datetime

# ----------------------------------------------------
# Comparison modules
# ----------------------------------------------------
from modules.group_rules import compare_group_rules
from modules.network_zones import compare_network_zones
from modules.session_policies import compare_session_policies
from modules.applications import compare_applications

# ----------------------------------------------------
# Extractor modules
# ----------------------------------------------------
from scripts.extract_groups import get_groups

app = Flask(__name__)
app.secret_key = "okta_compare_secret_key"


# ---------------------------------------------------
# Defaults
# ---------------------------------------------------
DEFAULT_ENV_A_DOMAIN = "haridemo.oktapreview.com"
DEFAULT_ENV_A_TOKEN  = "00FBlhQJCbNYGpa9WT-LxkDQTgVDlAqd1V2iibjeeH"

DEFAULT_ENV_B_DOMAIN = "lyraratna.oktapreview.com"
DEFAULT_ENV_B_TOKEN  = "00mtaZk6K-9APqAykFr1dfvR74oQ-EJmV0d1UdF3mu"


# ---------------------------------------------------
# Compare Groups (unchanged logic)
# ---------------------------------------------------
def compare_groups(groupsA, groupsB):
    diffs = []
    matches = []

    dictA = {g["profile"]["name"]: g for g in groupsA}
    dictB = {g["profile"]["name"]: g for g in groupsB}

    for name, grpA in dictA.items():
        descA = grpA["profile"].get("description", "")

        if name not in dictB:
            diffs.append({
                "Category": "Groups",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Access",
                "Recommended Action": f"Create group '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
        else:
            descB = dictB[name]["profile"].get("description", "")
            if descA != descB:
                diffs.append({
                    "Category": "Groups",
                    "Object": name,
                    "Attribute": "Description",
                    "Env A Value": descA,
                    "Env B Value": descB,
                    "Difference Type": "Mismatch",
                    "Impact": "Configuration Drift",
                    "Recommended Action": f"Align description for group '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Groups",
                    "Object": name,
                    "Attribute": "Description",
                    "Value": descA
                })

    # Extra in Env B
    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Groups",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Configuration Drift",
                "Recommended Action": f"Review/remove group '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches



# ---------------------------------------------------
# Main Page
# ---------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        # -------------
        # Inputs
        # -------------
        envA_domain = request.form.get("envA_domain", "").strip() or DEFAULT_ENV_A_DOMAIN
        envA_token  = request.form.get("envA_token", "").strip()  or DEFAULT_ENV_A_TOKEN

        envB_domain = request.form.get("envB_domain", "").strip() or DEFAULT_ENV_B_DOMAIN
        envB_token  = request.form.get("envB_token", "").strip()  or DEFAULT_ENV_B_TOKEN


        # ===================================================
        # GROUPS
        # ===================================================
        groupsA = get_groups(envA_domain, envA_token)
        groupsB = get_groups(envB_domain, envB_token)

        group_diffs, group_matches_raw = compare_groups(groupsA, groupsB)

        group_matches_display = [
            {
                "Category": m["Category"],
                "Object": m["Object"],
                "Attribute": m["Attribute"],
                "Env A Value": m["Value"],
                "Env B Value": m["Value"],
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match"
            }
            for m in group_matches_raw
        ]

        group_df = pd.DataFrame(group_diffs + group_matches_display)
        group_summary_counts = pd.DataFrame(group_diffs)["Priority"].value_counts().to_dict() if group_diffs else {}
        group_total_diff = len(group_diffs)


        # ===================================================
        # GROUP RULES
        # ===================================================
        rule_diffs, rule_matches_raw = compare_group_rules(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        rule_matches_display = [
            {
                "Category": m["Category"],
                "Object": m["Object"],
                "Attribute": m["Attribute"],
                "Env A Value": m["Value"],
                "Env B Value": m["Value"],
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match"
            } for m in rule_matches_raw
        ]

        rule_df = pd.DataFrame(rule_diffs + rule_matches_display)
        rule_summary_counts = pd.DataFrame(rule_diffs)["Priority"].value_counts().to_dict() if rule_diffs else {}
        rule_total_diff = len(rule_diffs)


        # ===================================================
        # NETWORK ZONES
        # ===================================================
        zone_diffs, zone_matches_raw = compare_network_zones(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        zone_matches_display = [
            {
                "Category": m["Category"],
                "Object": m["Object"],
                "Attribute": m["Attribute"],
                "Env A Value": m.get("Value", ""),
                "Env B Value": m.get("Value", ""),
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match"
            } for m in zone_matches_raw
        ]

        zone_df = pd.DataFrame(zone_diffs + zone_matches_display)
        zone_summary_counts = pd.DataFrame(zone_diffs)["Priority"].value_counts().to_dict() if zone_diffs else {}
        zone_total_diff = len(zone_diffs)


        # ===================================================
        # APPLICATIONS
        # ===================================================
        app_diffs, app_matches_raw = compare_applications(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        app_matches_display = [
            {
                "Category": m.get("Category", "Applications"),
                "Object": m.get("Object"),
                "Attribute": m.get("Attribute"),
                "Env A Value": m.get("Value", ""),
                "Env B Value": m.get("Value", ""),
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match"
            } for m in app_matches_raw
        ]

        apps_df = pd.DataFrame(app_diffs + app_matches_display)
        app_summary_counts = pd.DataFrame(app_diffs)["Priority"].value_counts().to_dict() if app_diffs else {}
        app_total_diff = len(app_diffs)


        # ===================================================
        # GLOBAL SESSION POLICIES (policies + rules together)
        # ===================================================
        session_diffs, session_matches_raw = compare_session_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        session_matches_display = [
            {
                "Category": m["Category"],
                "Object": m["Object"],
                "Attribute": m["Attribute"],
                "Env A Value": m["Value"],
                "Env B Value": m["Value"],
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match"
            }
            for m in session_matches_raw
        ]

        session_df = pd.DataFrame(session_diffs + session_matches_display)
        session_summary_counts = pd.DataFrame(session_diffs)["Priority"].value_counts().to_dict() if session_diffs else {}
        session_total_diff = len(session_diffs)


        # ===================================================
        # SESSION STORAGE
        # ===================================================
        session["session_diffs"] = session_diffs
        session["session_matches"] = session_matches_raw


        # ===================================================
        # Render Report
        # ===================================================
        return render_template(
            "oktacompare_report.html",

            # Groups
            group_df=group_df.to_dict(orient="records"),
            group_summary_counts=group_summary_counts,
            group_total_diff=group_total_diff,

            # Group Rules
            rule_df=rule_df.to_dict(orient="records"),
            rule_summary_counts=rule_summary_counts,
            rule_total_diff=rule_total_diff,

            # Network Zones
            zone_df=zone_df.to_dict(orient="records"),
            zone_summary_counts=zone_summary_counts,
            zone_total_diff=zone_total_diff,

            # Applications
            apps_df=apps_df.to_dict(orient="records"),
            app_summary_counts=app_summary_counts,
            app_total_diff=app_total_diff,

            # Global Session Policies (combined)
            session_df=session_df.to_dict(orient="records"),
            session_summary_counts=session_summary_counts,
            session_total_diff=session_total_diff,

            envA=envA_domain,
            envB=envB_domain,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


    return render_template("oktacompare_form.html")


# ---------------------------------------------------
# Run App
# ---------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
