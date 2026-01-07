import logging
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
from modules.authenticators import compare_authenticators
from modules.mfa_policies import compare_mfa_policies
from modules.password_policies import compare_password_policies
from modules.access_policies import compare_access_policies
from modules.idp_discovery_policies import compare_idp_discovery_policies
from modules.profile_enrollment_policies import compare_profile_enrollment_policies
from modules.brand_settings import compare_brand_settings
from modules.brand_pages import compare_brand_pages
from modules.brand_email_templates import compare_brand_email_templates

# ----------------------------------------------------
# Extractor modules
# ----------------------------------------------------
from scripts.extract_groups import get_groups

app = Flask(__name__)
app.secret_key = "okta_compare_secret_key"

# ---------------------------------------------------
# Logging
# ---------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


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
    logger.info("Index request received: method=%s", request.method)
    if request.method == "POST":

        # -------------
        # Inputs
        # -------------
        logger.info("Collecting input values (defaults used if blanks).")
        envA_domain = request.form.get("envA_domain", "").strip() or DEFAULT_ENV_A_DOMAIN
        envA_token  = request.form.get("envA_token", "").strip()  or DEFAULT_ENV_A_TOKEN

        envB_domain = request.form.get("envB_domain", "").strip() or DEFAULT_ENV_B_DOMAIN
        envB_token  = request.form.get("envB_token", "").strip()  or DEFAULT_ENV_B_TOKEN


        # ===================================================
        # GROUPS
        # ===================================================
        logger.info("Fetching groups for envA and envB.")
        groupsA = get_groups(envA_domain, envA_token)
        groupsB = get_groups(envB_domain, envB_token)

        logger.info("Comparing groups.")
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
        logger.info("Groups comparison complete: diffs=%s matches=%s", len(group_diffs), len(group_matches_raw))


        # ===================================================
        # GROUP RULES
        # ===================================================
        logger.info("Comparing group rules.")
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
        logger.info("Group rules comparison complete: diffs=%s matches=%s", len(rule_diffs), len(rule_matches_raw))


        # ===================================================
        # NETWORK ZONES
        # ===================================================
        logger.info("Comparing network zones.")
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
        logger.info("Network zones comparison complete: diffs=%s matches=%s", len(zone_diffs), len(zone_matches_raw))


        # ===================================================
        # APPLICATIONS
        # ===================================================
        logger.info("Comparing applications.")
        app_diffs, app_matches_raw = compare_applications(
            envA_domain, envA_token,
            envB_domain, envB_token,
            compare_group_assignments=False,
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
        logger.info("Applications comparison complete: diffs=%s matches=%s", len(app_diffs), len(app_matches_raw))

        # ===================================================
        # AUTHENTICATORS
        # ===================================================
        logger.info("Comparing authenticators.")
        auth_diffs, auth_matches_raw = compare_authenticators(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        auth_matches_display = [
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
            } for m in auth_matches_raw
        ]

        auth_df = pd.DataFrame(auth_diffs + auth_matches_display)
        auth_summary_counts = pd.DataFrame(auth_diffs)["Priority"].value_counts().to_dict() if auth_diffs else {}
        auth_total_diff = len(auth_diffs)
        logger.info("Authenticators comparison complete: diffs=%s matches=%s", len(auth_diffs), len(auth_matches_raw))

        # ===================================================
        # AUTHENTICATOR ENROLLMENT POLICIES (MFA)
        # ===================================================
        logger.info("Comparing authenticator enrollment policies.")
        mfa_diffs, mfa_matches_raw = compare_mfa_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        mfa_matches_display = [
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
            } for m in mfa_matches_raw
        ]

        mfa_df = pd.DataFrame(mfa_diffs + mfa_matches_display)
        mfa_summary_counts = pd.DataFrame(mfa_diffs)["Priority"].value_counts().to_dict() if mfa_diffs else {}
        mfa_total_diff = len(mfa_diffs)
        logger.info("MFA policies comparison complete: diffs=%s matches=%s", len(mfa_diffs), len(mfa_matches_raw))

        # ===================================================
        # PASSWORD POLICIES
        # ===================================================
        logger.info("Comparing password policies.")
        pwd_diffs, pwd_matches_raw = compare_password_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        pwd_matches_display = [
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
            } for m in pwd_matches_raw
        ]

        pwd_df = pd.DataFrame(pwd_diffs + pwd_matches_display)
        pwd_summary_counts = pd.DataFrame(pwd_diffs)["Priority"].value_counts().to_dict() if pwd_diffs else {}
        pwd_total_diff = len(pwd_diffs)
        logger.info("Password policies comparison complete: diffs=%s matches=%s", len(pwd_diffs), len(pwd_matches_raw))

        # ===================================================
        # APP SIGN-ON POLICIES (ACCESS_POLICY)
        # ===================================================
        logger.info("Comparing app sign-on policies.")
        access_diffs, access_matches_raw = compare_access_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        access_matches_display = [
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
            } for m in access_matches_raw
        ]

        access_df = pd.DataFrame(access_diffs + access_matches_display)
        access_summary_counts = pd.DataFrame(access_diffs)["Priority"].value_counts().to_dict() if access_diffs else {}
        access_total_diff = len(access_diffs)
        logger.info("App sign-on policies comparison complete: diffs=%s matches=%s", len(access_diffs), len(access_matches_raw))

        # ===================================================
        # IDP DISCOVERY POLICIES
        # ===================================================
        logger.info("Comparing IDP discovery policies.")
        idp_diffs, idp_matches_raw = compare_idp_discovery_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        idp_matches_display = [
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
            } for m in idp_matches_raw
        ]

        idp_df = pd.DataFrame(idp_diffs + idp_matches_display)
        idp_summary_counts = pd.DataFrame(idp_diffs)["Priority"].value_counts().to_dict() if idp_diffs else {}
        idp_total_diff = len(idp_diffs)
        logger.info("IDP discovery policies comparison complete: diffs=%s matches=%s", len(idp_diffs), len(idp_matches_raw))

        # ===================================================
        # PROFILE ENROLLMENT POLICIES
        # ===================================================
        logger.info("Comparing profile enrollment policies.")
        profile_diffs, profile_matches_raw = compare_profile_enrollment_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        profile_matches_display = [
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
            } for m in profile_matches_raw
        ]

        profile_df = pd.DataFrame(profile_diffs + profile_matches_display)
        profile_summary_counts = pd.DataFrame(profile_diffs)["Priority"].value_counts().to_dict() if profile_diffs else {}
        profile_total_diff = len(profile_diffs)
        logger.info(
            "Profile enrollment policies comparison complete: diffs=%s matches=%s",
            len(profile_diffs),
            len(profile_matches_raw),
        )

        # ===================================================
        # BRAND SETTINGS
        # ===================================================
        logger.info("Comparing brand settings.")
        brand_diffs, brand_matches_raw = compare_brand_settings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        brand_matches_display = [
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
            } for m in brand_matches_raw
        ]

        brand_df = pd.DataFrame(brand_diffs + brand_matches_display)
        brand_summary_counts = pd.DataFrame(brand_diffs)["Priority"].value_counts().to_dict() if brand_diffs else {}
        brand_total_diff = len(brand_diffs)
        logger.info("Brand settings comparison complete: diffs=%s matches=%s", len(brand_diffs), len(brand_matches_raw))

        # ===================================================
        # BRAND PAGES
        # ===================================================
        logger.info("Comparing brand pages.")
        brand_pages_diffs, brand_pages_matches_raw = compare_brand_pages(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        brand_pages_matches_display = [
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
            } for m in brand_pages_matches_raw
        ]

        brand_pages_df = pd.DataFrame(brand_pages_diffs + brand_pages_matches_display)
        brand_pages_summary_counts = (
            pd.DataFrame(brand_pages_diffs)["Priority"].value_counts().to_dict() if brand_pages_diffs else {}
        )
        brand_pages_total_diff = len(brand_pages_diffs)
        logger.info(
            "Brand pages comparison complete: diffs=%s matches=%s",
            len(brand_pages_diffs),
            len(brand_pages_matches_raw),
        )

        # ===================================================
        # BRAND EMAIL TEMPLATES
        # ===================================================
        logger.info("Comparing brand email templates.")
        brand_email_diffs, brand_email_matches_raw = compare_brand_email_templates(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        brand_email_matches_display = [
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
            } for m in brand_email_matches_raw
        ]

        brand_email_df = pd.DataFrame(brand_email_diffs + brand_email_matches_display)
        brand_email_summary_counts = (
            pd.DataFrame(brand_email_diffs)["Priority"].value_counts().to_dict() if brand_email_diffs else {}
        )
        brand_email_total_diff = len(brand_email_diffs)
        logger.info(
            "Brand email templates comparison complete: diffs=%s matches=%s",
            len(brand_email_diffs),
            len(brand_email_matches_raw),
        )


        # ===================================================
        # GLOBAL SESSION POLICIES (policies + rules together)
        # ===================================================
        logger.info("Comparing session policies.")
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
        logger.info("Session policies comparison complete: diffs=%s matches=%s", len(session_diffs), len(session_matches_raw))


        # ===================================================
        # SESSION STORAGE
        # ===================================================
        logger.info("Storing session results.")
        session["session_diffs"] = session_diffs
        session["session_matches"] = session_matches_raw


        # ===================================================
        # Render Report
        # ===================================================
        logger.info("Rendering report for envA=%s envB=%s.", envA_domain, envB_domain)
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

            # Authenticators
            auth_df=auth_df.to_dict(orient="records"),
            auth_summary_counts=auth_summary_counts,
            auth_total_diff=auth_total_diff,

            # Authenticator Enrollment Policies (MFA)
            mfa_df=mfa_df.to_dict(orient="records"),
            mfa_summary_counts=mfa_summary_counts,
            mfa_total_diff=mfa_total_diff,

            # Password Policies
            pwd_df=pwd_df.to_dict(orient="records"),
            pwd_summary_counts=pwd_summary_counts,
            pwd_total_diff=pwd_total_diff,

            # App Sign-On Policies
            access_df=access_df.to_dict(orient="records"),
            access_summary_counts=access_summary_counts,
            access_total_diff=access_total_diff,

            # IDP Discovery Policies
            idp_df=idp_df.to_dict(orient="records"),
            idp_summary_counts=idp_summary_counts,
            idp_total_diff=idp_total_diff,

            # Profile Enrollment Policies
            profile_df=profile_df.to_dict(orient="records"),
            profile_summary_counts=profile_summary_counts,
            profile_total_diff=profile_total_diff,

            # Brand Settings
            brand_df=brand_df.to_dict(orient="records"),
            brand_summary_counts=brand_summary_counts,
            brand_total_diff=brand_total_diff,

            # Brand Pages
            brand_pages_df=brand_pages_df.to_dict(orient="records"),
            brand_pages_summary_counts=brand_pages_summary_counts,
            brand_pages_total_diff=brand_pages_total_diff,

            # Brand Email Templates
            brand_email_df=brand_email_df.to_dict(orient="records"),
            brand_email_summary_counts=brand_email_summary_counts,
            brand_email_total_diff=brand_email_total_diff,

            # Global Session Policies (combined)
            session_df=session_df.to_dict(orient="records"),
            session_summary_counts=session_summary_counts,
            session_total_diff=session_total_diff,

            envA=envA_domain,
            envB=envB_domain,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


    logger.info("Rendering input form.")
    return render_template("oktacompare_form.html")


# ---------------------------------------------------
# Run App
# ---------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting OktaCompare Flask app.")
    app.run(debug=True, port=5000)
