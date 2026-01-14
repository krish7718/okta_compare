import logging
import json
import requests
import pandas as pd
import io
import csv
from flask import Flask, session, request, render_template, send_file, send_from_directory, redirect, url_for
from datetime import datetime
from zoneinfo import ZoneInfo

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
from modules.authorization_servers_settings import compare_authorization_servers_settings
from modules.authorization_servers_access_policies import compare_authorization_servers_access_policies
from modules.custom_admin_roles import compare_custom_admin_roles
from modules.resource_sets import compare_resource_sets
from modules.admin_assignments import compare_admin_assignments
from modules.api_tokens import compare_api_tokens
from modules.security_general_settings import compare_security_general_settings
from modules.org_settings import compare_org_settings
from modules.identity_providers import compare_identity_providers
from modules.realms import compare_realms, compare_realm_assignments
from modules.profile_schema_user import compare_user_profile_schema
from modules.profile_mappings import compare_profile_mappings
from modules.trusted_origins import compare_trusted_origins
from modules.okta_view_guide import build_okta_view_guide

# ----------------------------------------------------
# Extractor modules
# ----------------------------------------------------
from scripts.extract_groups import get_groups

app = Flask(__name__)
app.secret_key = "okta_compare_secret_key"
LAST_EXPORT = {"diffs": [], "matches": []}
OKTA_VIEW_EXPORT = {"rows": []}
OKTA_VIEW_GUIDE = {"sections": [], "domain": ""}

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
        session.clear()

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
        # AUTHORIZATION SERVERS - SETTINGS
        # ===================================================
        logger.info("Comparing authorization servers settings.")
        authz_diffs, authz_matches_raw = compare_authorization_servers_settings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        authz_matches_display = [
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
            } for m in authz_matches_raw
        ]

        authz_df = pd.DataFrame(authz_diffs + authz_matches_display)
        authz_summary_counts = pd.DataFrame(authz_diffs)["Priority"].value_counts().to_dict() if authz_diffs else {}
        authz_total_diff = len(authz_diffs)
        logger.info("Authorization servers settings comparison complete: diffs=%s matches=%s", len(authz_diffs), len(authz_matches_raw))

        # ===================================================
        # AUTHORIZATION SERVERS - ACCESS POLICIES
        # ===================================================
        logger.info("Comparing authorization servers access policies.")
        authz_policy_diffs, authz_policy_matches_raw = compare_authorization_servers_access_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        authz_policy_matches_display = [
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
            } for m in authz_policy_matches_raw
        ]

        authz_policy_df = pd.DataFrame(authz_policy_diffs + authz_policy_matches_display)
        authz_policy_summary_counts = (
            pd.DataFrame(authz_policy_diffs)["Priority"].value_counts().to_dict() if authz_policy_diffs else {}
        )
        authz_policy_total_diff = len(authz_policy_diffs)
        logger.info(
            "Authorization servers access policies comparison complete: diffs=%s matches=%s",
            len(authz_policy_diffs),
            len(authz_policy_matches_raw),
        )

        # ===================================================
        # CUSTOM ADMIN ROLES
        # ===================================================
        logger.info("Comparing custom admin roles.")
        admin_role_diffs, admin_role_matches_raw = compare_custom_admin_roles(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        admin_role_matches_display = [
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
            } for m in admin_role_matches_raw
        ]

        admin_role_df = pd.DataFrame(admin_role_diffs + admin_role_matches_display)
        admin_role_summary_counts = (
            pd.DataFrame(admin_role_diffs)["Priority"].value_counts().to_dict() if admin_role_diffs else {}
        )
        admin_role_total_diff = len(admin_role_diffs)
        logger.info(
            "Custom admin roles comparison complete: diffs=%s matches=%s",
            len(admin_role_diffs),
            len(admin_role_matches_raw),
        )

        # ===================================================
        # RESOURCE SETS
        # ===================================================
        logger.info("Comparing resource sets.")
        resource_set_diffs, resource_set_matches_raw = compare_resource_sets(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        resource_set_matches_display = [
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
            } for m in resource_set_matches_raw
        ]

        resource_set_df = pd.DataFrame(resource_set_diffs + resource_set_matches_display)
        resource_set_summary_counts = (
            pd.DataFrame(resource_set_diffs)["Priority"].value_counts().to_dict() if resource_set_diffs else {}
        )
        resource_set_total_diff = len(resource_set_diffs)
        logger.info(
            "Resource sets comparison complete: diffs=%s matches=%s",
            len(resource_set_diffs),
            len(resource_set_matches_raw),
        )

        # ===================================================
        # ADMIN ASSIGNMENTS
        # ===================================================
        logger.info("Comparing admin assignments.")
        admin_assign_diffs, admin_assign_matches_raw = compare_admin_assignments(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        admin_assign_matches_display = [
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
            } for m in admin_assign_matches_raw
        ]

        admin_assign_df = pd.DataFrame(admin_assign_diffs + admin_assign_matches_display)
        admin_assign_summary_counts = (
            pd.DataFrame(admin_assign_diffs)["Priority"].value_counts().to_dict() if admin_assign_diffs else {}
        )
        admin_assign_total_diff = len(admin_assign_diffs)
        logger.info(
            "Admin assignments comparison complete: diffs=%s matches=%s",
            len(admin_assign_diffs),
            len(admin_assign_matches_raw),
        )

        # ===================================================
        # API TOKENS
        # ===================================================
        logger.info("Comparing API tokens.")
        api_token_diffs, api_token_matches_raw = compare_api_tokens(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        api_token_matches_display = [
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
            } for m in api_token_matches_raw
        ]

        api_token_df = pd.DataFrame(api_token_diffs + api_token_matches_display)
        api_token_summary_counts = (
            pd.DataFrame(api_token_diffs)["Priority"].value_counts().to_dict() if api_token_diffs else {}
        )
        api_token_total_diff = len(api_token_diffs)
        logger.info(
            "API tokens comparison complete: diffs=%s matches=%s",
            len(api_token_diffs),
            len(api_token_matches_raw),
        )

        # ===================================================
        # SECURITY GENERAL SETTINGS
        # ===================================================
        logger.info("Comparing security general settings.")
        sec_diffs, sec_matches_raw = compare_security_general_settings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        sec_matches_display = [
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
            } for m in sec_matches_raw
        ]

        sec_df = pd.DataFrame(sec_diffs + sec_matches_display)
        sec_summary_counts = (
            pd.DataFrame(sec_diffs)["Priority"].value_counts().to_dict() if sec_diffs else {}
        )
        sec_total_diff = len(sec_diffs)
        logger.info(
            "Security general settings comparison complete: diffs=%s matches=%s",
            len(sec_diffs),
            len(sec_matches_raw),
        )

        # ===================================================
        # ORG GENERAL SETTINGS
        # ===================================================
        logger.info("Comparing org general settings.")
        org_diffs, org_matches_raw = compare_org_settings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        org_matches_display = [
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
            } for m in org_matches_raw
        ]

        org_df = pd.DataFrame(org_diffs + org_matches_display)
        org_summary_counts = (
            pd.DataFrame(org_diffs)["Priority"].value_counts().to_dict() if org_diffs else {}
        )
        org_total_diff = len(org_diffs)
        logger.info(
            "Org general settings comparison complete: diffs=%s matches=%s",
            len(org_diffs),
            len(org_matches_raw),
        )

        # ===================================================
        # IDENTITY PROVIDERS
        # ===================================================
        logger.info("Comparing identity providers.")
        idp_provider_diffs, idp_provider_matches_raw = compare_identity_providers(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        idp_provider_matches_display = [
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
            } for m in idp_provider_matches_raw
        ]

        idp_provider_df = pd.DataFrame(idp_provider_diffs + idp_provider_matches_display)
        idp_provider_summary_counts = (
            pd.DataFrame(idp_provider_diffs)["Priority"].value_counts().to_dict() if idp_provider_diffs else {}
        )
        idp_provider_total_diff = len(idp_provider_diffs)
        logger.info(
            "Identity providers comparison complete: diffs=%s matches=%s",
            len(idp_provider_diffs),
            len(idp_provider_matches_raw),
        )

        # ===================================================
        # REALMS
        # ===================================================
        logger.info("Comparing realms.")
        realm_diffs, realm_matches_raw = compare_realms(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        realm_matches_display = [
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
            } for m in realm_matches_raw
        ]

        realm_df = pd.DataFrame(realm_diffs + realm_matches_display)
        realm_summary_counts = (
            pd.DataFrame(realm_diffs)["Priority"].value_counts().to_dict() if realm_diffs else {}
        )
        realm_total_diff = len(realm_diffs)
        logger.info(
            "Realms comparison complete: diffs=%s matches=%s",
            len(realm_diffs),
            len(realm_matches_raw),
        )

        # ===================================================
        # REALM ASSIGNMENTS
        # ===================================================
        logger.info("Comparing realm assignments.")
        realm_assign_diffs, realm_assign_matches_raw = compare_realm_assignments(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        realm_assign_matches_display = [
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
            } for m in realm_assign_matches_raw
        ]

        realm_assign_df = pd.DataFrame(realm_assign_diffs + realm_assign_matches_display)
        realm_assign_summary_counts = (
            pd.DataFrame(realm_assign_diffs)["Priority"].value_counts().to_dict() if realm_assign_diffs else {}
        )
        realm_assign_total_diff = len(realm_assign_diffs)
        logger.info(
            "Realm assignments comparison complete: diffs=%s matches=%s",
            len(realm_assign_diffs),
            len(realm_assign_matches_raw),
        )

        # ===================================================
        # PROFILE SCHEMA - USER
        # ===================================================
        logger.info("Comparing user profile schema.")
        schema_diffs, schema_matches_raw = compare_user_profile_schema(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        schema_matches_display = [
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
            } for m in schema_matches_raw
        ]

        schema_df = pd.DataFrame(schema_diffs + schema_matches_display)
        schema_summary_counts = (
            pd.DataFrame(schema_diffs)["Priority"].value_counts().to_dict() if schema_diffs else {}
        )
        schema_total_diff = len(schema_diffs)
        logger.info(
            "User profile schema comparison complete: diffs=%s matches=%s",
            len(schema_diffs),
            len(schema_matches_raw),
        )

        # ===================================================
        # PROFILE MAPPINGS
        # ===================================================
        logger.info("Comparing profile mappings.")
        mapping_diffs, mapping_matches_raw = compare_profile_mappings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        mapping_matches_display = [
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
            } for m in mapping_matches_raw
        ]

        mapping_df = pd.DataFrame(mapping_diffs + mapping_matches_display)
        mapping_summary_counts = (
            pd.DataFrame(mapping_diffs)["Priority"].value_counts().to_dict() if mapping_diffs else {}
        )
        mapping_total_diff = len(mapping_diffs)
        logger.info(
            "Profile mappings comparison complete: diffs=%s matches=%s",
            len(mapping_diffs),
            len(mapping_matches_raw),
        )

        # ===================================================
        # TRUSTED ORIGINS
        # ===================================================
        logger.info("Comparing trusted origins.")
        origin_diffs, origin_matches_raw = compare_trusted_origins(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        origin_matches_display = [
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
            } for m in origin_matches_raw
        ]

        origin_df = pd.DataFrame(origin_diffs + origin_matches_display)
        origin_summary_counts = (
            pd.DataFrame(origin_diffs)["Priority"].value_counts().to_dict() if origin_diffs else {}
        )
        origin_total_diff = len(origin_diffs)
        logger.info(
            "Trusted origins comparison complete: diffs=%s matches=%s",
            len(origin_diffs),
            len(origin_matches_raw),
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
        all_diffs = (
            group_diffs
            + rule_diffs
            + zone_diffs
            + app_diffs
            + session_diffs
            + auth_diffs
            + mfa_diffs
            + pwd_diffs
            + access_diffs
            + idp_diffs
            + profile_diffs
            + brand_diffs
            + brand_pages_diffs
            + brand_email_diffs
            + authz_diffs
            + authz_policy_diffs
            + admin_role_diffs
            + resource_set_diffs
            + admin_assign_diffs
            + api_token_diffs
            + sec_diffs
            + org_diffs
            + idp_provider_diffs
            + realm_diffs
            + realm_assign_diffs
            + schema_diffs
            + mapping_diffs
            + origin_diffs
        )
        all_matches_raw = (
            group_matches_raw
            + rule_matches_raw
            + zone_matches_raw
            + app_matches_raw
            + session_matches_raw
            + auth_matches_raw
            + mfa_matches_raw
            + pwd_matches_raw
            + access_matches_raw
            + idp_matches_raw
            + profile_matches_raw
            + brand_matches_raw
            + brand_pages_matches_raw
            + brand_email_matches_raw
            + authz_matches_raw
            + authz_policy_matches_raw
            + admin_role_matches_raw
            + resource_set_matches_raw
            + admin_assign_matches_raw
            + api_token_matches_raw
            + sec_matches_raw
            + org_matches_raw
            + idp_provider_matches_raw
            + realm_matches_raw
            + realm_assign_matches_raw
            + schema_matches_raw
            + mapping_matches_raw
            + origin_matches_raw
        )
        LAST_EXPORT["diffs"] = all_diffs
        LAST_EXPORT["matches"] = all_matches_raw
        export_bytes = (
            len(json.dumps(all_diffs, default=str).encode("utf-8"))
            + len(json.dumps(all_matches_raw, default=str).encode("utf-8"))
        )
        logger.info("Export payload size: %.2f KB", export_bytes / 1024)


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

            # Authorization Servers - Settings
            authz_df=authz_df.to_dict(orient="records"),
            authz_summary_counts=authz_summary_counts,
            authz_total_diff=authz_total_diff,

            # Authorization Servers - Access Policies
            authz_policy_df=authz_policy_df.to_dict(orient="records"),
            authz_policy_summary_counts=authz_policy_summary_counts,
            authz_policy_total_diff=authz_policy_total_diff,

            # Custom Admin Roles
            admin_role_df=admin_role_df.to_dict(orient="records"),
            admin_role_summary_counts=admin_role_summary_counts,
            admin_role_total_diff=admin_role_total_diff,

            # Resource Sets
            resource_set_df=resource_set_df.to_dict(orient="records"),
            resource_set_summary_counts=resource_set_summary_counts,
            resource_set_total_diff=resource_set_total_diff,

            # Admin Assignments
            admin_assign_df=admin_assign_df.to_dict(orient="records"),
            admin_assign_summary_counts=admin_assign_summary_counts,
            admin_assign_total_diff=admin_assign_total_diff,

            # API Tokens
            api_token_df=api_token_df.to_dict(orient="records"),
            api_token_summary_counts=api_token_summary_counts,
            api_token_total_diff=api_token_total_diff,

            # Security General Settings
            sec_df=sec_df.to_dict(orient="records"),
            sec_summary_counts=sec_summary_counts,
            sec_total_diff=sec_total_diff,

            # Org General Settings
            org_df=org_df.to_dict(orient="records"),
            org_summary_counts=org_summary_counts,
            org_total_diff=org_total_diff,

            # Identity Providers
            idp_provider_df=idp_provider_df.to_dict(orient="records"),
            idp_provider_summary_counts=idp_provider_summary_counts,
            idp_provider_total_diff=idp_provider_total_diff,

            # Realms
            realm_df=realm_df.to_dict(orient="records"),
            realm_summary_counts=realm_summary_counts,
            realm_total_diff=realm_total_diff,

            # Realm Assignments
            realm_assign_df=realm_assign_df.to_dict(orient="records"),
            realm_assign_summary_counts=realm_assign_summary_counts,
            realm_assign_total_diff=realm_assign_total_diff,

            # Profile Schema - User
            schema_df=schema_df.to_dict(orient="records"),
            schema_summary_counts=schema_summary_counts,
            schema_total_diff=schema_total_diff,

            # Profile Mappings
            mapping_df=mapping_df.to_dict(orient="records"),
            mapping_summary_counts=mapping_summary_counts,
            mapping_total_diff=mapping_total_diff,

            # Trusted Origins
            origin_df=origin_df.to_dict(orient="records"),
            origin_summary_counts=origin_summary_counts,
            origin_total_diff=origin_total_diff,

            # Global Session Policies (combined)
            session_df=session_df.to_dict(orient="records"),
            session_summary_counts=session_summary_counts,
            session_total_diff=session_total_diff,

            envA=envA_domain,
            envB=envB_domain,
            generated_at=datetime.now(ZoneInfo("Australia/Brisbane")).strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            ),
        )


    logger.info("Rendering input form.")
    return render_template("oktacompare_form.html")


def _export_rows(rows, export_type):
    fieldnames = [
        "Entity",
        "Object",
        "Attribute",
        "Env A Value",
        "Env B Value",
        "Difference Type",
        "Impact",
        "Recommended Action",
        "Priority",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        if export_type == "matches":
            value = row.get("Value", "")
            export_row = {
                "Entity": row.get("Category", ""),
                "Object": row.get("Object", ""),
                "Attribute": row.get("Attribute", ""),
                "Env A Value": value,
                "Env B Value": value,
                "Difference Type": "Match",
                "Impact": "",
                "Recommended Action": "",
                "Priority": "🟢 Match",
            }
        else:
            export_row = {
                "Entity": row.get("Category", ""),
                "Object": row.get("Object", ""),
                "Attribute": row.get("Attribute", ""),
                "Env A Value": row.get("Env A Value", ""),
                "Env B Value": row.get("Env B Value", ""),
                "Difference Type": row.get("Difference Type", ""),
                "Impact": row.get("Impact", ""),
                "Recommended Action": row.get("Recommended Action", ""),
                "Priority": row.get("Priority", ""),
            }
        writer.writerow(export_row)

    output.seek(0)
    return output


def _export_comparison_rows(diffs, matches):
    fieldnames = [
        "Category",
        "Object",
        "Attribute",
        "Env A Value",
        "Env B Value",
        "Difference Type",
        "Impact",
        "Recommended Action",
        "Priority",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    def _clean_priority(value):
        if not value:
            return ""
        normalized = str(value)
        for token in ("🔴", "🟠", "🟡", "🟢"):
            normalized = normalized.replace(token, "")
        return normalized.strip()

    for row in diffs:
        writer.writerow({
            "Category": row.get("Category", ""),
            "Object": row.get("Object", ""),
            "Attribute": row.get("Attribute", ""),
            "Env A Value": row.get("Env A Value", ""),
            "Env B Value": row.get("Env B Value", ""),
            "Difference Type": row.get("Difference Type", ""),
            "Impact": row.get("Impact", ""),
            "Recommended Action": row.get("Recommended Action", ""),
            "Priority": _clean_priority(row.get("Priority", "")),
        })

    for row in matches:
        value = row.get("Value", "")
        writer.writerow({
            "Category": row.get("Category", ""),
            "Object": row.get("Object", ""),
            "Attribute": row.get("Attribute", ""),
            "Env A Value": value,
            "Env B Value": value,
            "Difference Type": "Match",
            "Impact": "",
            "Recommended Action": "",
            "Priority": "Match",
        })

    output.seek(0)
    return output


@app.route("/export_report")
def export_report():
    diffs = LAST_EXPORT.get("diffs", [])
    matches = LAST_EXPORT.get("matches", [])
    if not diffs and not matches:
        logger.warning("No comparison data found in session or server cache for export.")
    output = _export_comparison_rows(diffs, matches)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="okta_compare_report.csv",
    )


@app.route("/export_differences")
def export_differences():
    diffs = LAST_EXPORT.get("diffs", [])
    if not diffs:
        logger.warning("No differences found in session or server cache for export.")
    output = _export_rows(diffs, "diffs")
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="okta_compare_differences.csv",
    )


@app.route("/export_matches")
def export_matches():
    matches = LAST_EXPORT.get("matches", [])
    if not matches:
        logger.warning("No matches found in session or server cache for export.")
    output = _export_rows(matches, "matches")
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="okta_compare_matches.csv",
    )

@app.errorhandler(requests.exceptions.ReadTimeout)
def handle_read_timeout(error):
    logger.error("Upstream timeout: %s", error)
    return render_template(
        "oktacompare_error.html",
        title="Request Timed Out",
        message="Okta took too long to respond. Please try again in a moment.",
    ), 504


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception("Unhandled error: %s", error)
    return render_template(
        "oktacompare_error.html",
        title="Something Went Wrong",
        message="We hit an unexpected error while building the report. Please retry.",
    ), 500

@app.route("/snapshot", methods=["GET"])
def okta_view():
    logger.info("Rendering OktaSnapshot form.")
    return render_template("okta_view_form.html")


@app.route("/snapshot", methods=["POST"])
def okta_view_generate():
    domain = (request.form.get("domain") or "").strip() or DEFAULT_ENV_A_DOMAIN
    api_token = (request.form.get("api_token") or "").strip() or DEFAULT_ENV_A_TOKEN

    logger.info("Generating OktaSnapshot guide for %s.", domain)
    sections, export_rows = build_okta_view_guide(domain, api_token)
    OKTA_VIEW_EXPORT["rows"] = export_rows
    OKTA_VIEW_GUIDE["sections"] = sections
    OKTA_VIEW_GUIDE["domain"] = domain

    return redirect(url_for("okta_view_guide"))


@app.route("/snapshot/guide", methods=["GET"])
def okta_view_guide():
    sections = OKTA_VIEW_GUIDE.get("sections") or []
    domain = OKTA_VIEW_GUIDE.get("domain") or DEFAULT_ENV_A_DOMAIN
    return render_template(
        "okta_view_report.html",
        guide_sections=sections,
        guide_domain=domain,
        guide_generated_at=datetime.now(ZoneInfo("Australia/Brisbane")).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
    )


@app.route("/snapshot/export", methods=["GET"])
def okta_view_export():
    sections = OKTA_VIEW_GUIDE.get("sections") or []
    domain = OKTA_VIEW_GUIDE.get("domain") or DEFAULT_ENV_A_DOMAIN
    if not sections:
        logger.warning("No OktaSnapshot guide data found for export.")
    try:
        from weasyprint import HTML
    except Exception:
        logger.exception("WeasyPrint not available for PDF export.")
        return render_template(
            "oktacompare_error.html",
            title="PDF Export Unavailable",
            message="PDF export requires WeasyPrint. Please install it and retry.",
        ), 500

    html = render_template(
        "okta_view_pdf.html",
        guide_sections=sections,
        guide_domain=domain,
    )
    pdf = HTML(string=html).write_pdf()
    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="okta_view_guide.pdf",
    )


@app.route("/evaluate", methods=["GET"])
def okta_evaluate():
    logger.info("Rendering OktaEvaluate placeholder.")
    return render_template("okta_evaluate.html")


@app.route("/migrate", methods=["GET"])
def okta_migrate():
    logger.info("Rendering OktaMigrate placeholder.")
    return render_template("okta_migrate.html")


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory("templates/static", filename)


# ---------------------------------------------------
# Run App
# ---------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting OktaCompare Flask app.")
    app.run(debug=False, port=5000)
