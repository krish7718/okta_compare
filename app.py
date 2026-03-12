import logging
import json
import re
import requests
import pandas as pd
import io
import csv
from flask import Flask, session, request, render_template, send_file, send_from_directory, redirect, url_for
from datetime import datetime
from zoneinfo import ZoneInfo
from werkzeug.exceptions import HTTPException

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
from modules.event_hooks import compare_event_hooks
from modules.inline_hooks import compare_inline_hooks
from modules.attack_protection import compare_attack_protection
from modules.group_push_mappings import compare_group_push_mappings
from modules.entity_risk_policies import compare_entity_risk_policies
from modules.post_auth_session_policies import compare_post_auth_session_policies
from modules.oktasnapshot_guide import build_oktasnapshot_guide

# ----------------------------------------------------
# Extractor modules
# ----------------------------------------------------
from scripts.extract_groups import get_groups
from scripts.extract_applications import get_applications as get_all_applications

app = Flask(__name__)
app.secret_key = "okta_compare_secret_key"
LAST_EXPORT = {"diffs": [], "matches": []}
OKTASNAPSHOT_EXPORT = {"rows": []}
OKTASNAPSHOT_GUIDE = {"sections": [], "domain": ""}
OKTAEVALUATE_EXPORT = {"evaluation": None}
OKTAMIGRATE_EXPORT = {
    "plan": None,
    "group_sync": None,
    "source_domain": "",
    "source_token": "",
    "target_domain": "",
    "target_token": "",
}

# ---------------------------------------------------
# Logging
# ---------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _section_map(sections):
    return {section.get("id"): section for section in (sections or [])}


def _ensure_https_domain(domain):
    return domain if str(domain).startswith(("http://", "https://")) else f"https://{domain}"


def _as_dict(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _walk_nested(value, path=""):
    if isinstance(value, dict):
        for key, nested in value.items():
            next_path = f"{path}.{key}" if path else str(key)
            yield from _walk_nested(nested, next_path)
    elif isinstance(value, list):
        for idx, nested in enumerate(value):
            next_path = f"{path}[{idx}]"
            yield from _walk_nested(nested, next_path)
    else:
        yield path, value


def _is_deny_action(actions):
    for path, value in _walk_nested(actions):
        if isinstance(value, str) and value.strip().lower() == "deny":
            return True, path
    for path, value in _walk_nested(actions):
        if isinstance(value, str) and "deny" in value.strip().lower():
            return True, path
    return False, ""


def _extract_session_timeout_findings(actions, threshold_minutes=120):
    findings = []
    for path, value in _walk_nested(actions):
        if not isinstance(value, (int, float)):
            continue
        p = path.lower()
        if "session" not in p and "idle" not in p and "lifetime" not in p:
            continue

        minutes = None
        unit = None
        if "minute" in p:
            minutes = float(value)
            unit = "minutes"
        elif "second" in p:
            minutes = float(value) / 60.0
            unit = "seconds"
        elif "hour" in p:
            minutes = float(value) * 60.0
            unit = "hours"
        elif any(k in p for k in ["maxsession", "idle", "lifetime"]):
            # Fallback heuristic: assume minutes for session timeout-like fields without explicit unit
            minutes = float(value)
            unit = "assumed-minutes"

        if minutes is not None and minutes > threshold_minutes:
            findings.append(
                {
                    "path": path,
                    "value": value,
                    "unit": unit,
                    "minutes": round(minutes, 2),
                }
            )
    return findings


def _find_setting_value(rows, setting_name):
    for row in rows or []:
        if (row.get("Setting") or "").strip().lower() == setting_name.strip().lower():
            return row.get("Value")
    return None


def _status_from_boolish_enabled(value):
    if value is None:
        return "Info"
    normalized = str(value).strip().lower()
    if normalized in {"enabled", "yes", "true"}:
        return "Pass"
    if normalized in {"disabled", "not enabled", "no", "false"}:
        return "Warning"
    return "Info"


def _validation(title, status, summary, items=None, severity=None):
    return {
        "title": title,
        "status": status,
        "severity": severity,
        "summary": summary,
        "items": items or [],
    }


def _extract_minutes_from_label(text):
    if text is None:
        return None
    s = str(text).strip().lower()
    if not s:
        return None
    m = re.search(r"(\d+)\s*hour", s)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r"(\d+)\s*minute", s)
    if m:
        return int(m.group(1))
    return None


def _password_policy_weaknesses(policy_row):
    weaknesses = []
    complexity = str(policy_row.get("Complexity Settings") or "")
    age = str(policy_row.get("Age Settings") or "")
    lockout = str(policy_row.get("Lockout Settings") or "")

    min_len = None
    m = re.search(r"Minimum length:\s*(\d+)", complexity, re.IGNORECASE)
    if m:
        min_len = int(m.group(1))
        if min_len < 12:
            weaknesses.append(f"minimum length {min_len} (< 12)")

    for label in ["Lower case letters", "Upper case letters", "Numbers", "Symbols"]:
        m = re.search(rf"{re.escape(label)}:\s*(\d+)", complexity, re.IGNORECASE)
        if m and int(m.group(1)) == 0:
            weaknesses.append(f"{label.lower()} requirement is 0")

    if "Restrict use of common passwords: Disabled" in complexity:
        weaknesses.append("common password restriction disabled")
    if "Does not contain part of username: No" in complexity:
        weaknesses.append("username exclusion disabled")

    min_age = _extract_minutes_from_label(re.search(r"Minimum password age:\s*([^;]+)", age, re.IGNORECASE).group(1)) if re.search(r"Minimum password age:\s*([^;]+)", age, re.IGNORECASE) else None
    if min_age is not None and min_age == 0:
        weaknesses.append("minimum password age is 0")

    lockout_attempts = re.search(r"Lock out after failed attempts:\s*(\d+)", lockout, re.IGNORECASE)
    if lockout_attempts and int(lockout_attempts.group(1)) > 10:
        weaknesses.append(f"lockout attempts threshold {lockout_attempts.group(1)} (> 10)")

    return weaknesses


def _mfa_policy_has_optional_factors(policy_row):
    settings = _as_dict(policy_row.get("Settings"))
    for _, value in _walk_nested(settings):
        if isinstance(value, str) and value.strip().upper() == "OPTIONAL":
            return True
    return False


def _mfa_policy_weak_factors(policy_row):
    settings = _as_dict(policy_row.get("Settings"))
    weak_factor_hits = set()
    weak_tokens = {
        "sms": "SMS",
        "voice": "Voice",
        "call": "Voice",
        "security_question": "Security Question",
        "question": "Security Question",
        "email": "Email",
    }
    for path, value in _walk_nested(settings):
        p = path.lower()
        matched = None
        for token, label in weak_tokens.items():
            if token in p:
                matched = label
                break
        if not matched:
            continue
        if isinstance(value, str):
            v = value.strip().upper()
            if v in {"OPTIONAL", "REQUIRED", "ACTIVE", "ENABLED"}:
                weak_factor_hits.add(matched)
        elif isinstance(value, bool) and value:
            weak_factor_hits.add(matched)
    return sorted(weak_factor_hits)


def _run_security_validations(sections, extra_context=None):
    section_by_id = _section_map(sections)
    extra_context = extra_context or {}
    validations = []

    # Validation 1: Catch-all/default rule deny posture in authentication/app sign-on policies
    auth_section = section_by_id.get("authentication-policies") or {}
    auth_rows = auth_section.get("rows") or []
    auth_rule_rows = [r for r in auth_rows if (r.get("Entry Type") == "Rule")]

    policy_map = {}
    for row in auth_rule_rows:
        policy_name = row.get("Policy Name") or "Unknown Policy"
        rule_name = (row.get("Rule Name") or "").strip()
        if not rule_name:
            continue
        bucket = policy_map.setdefault(policy_name, {"catch_all_found": False, "catch_all_denied": False, "details": []})
        is_catch_all = any(token in rule_name.lower() for token in ["catch", "default", "all"])
        actions = _as_dict(row.get("Actions"))
        is_deny, deny_path = _is_deny_action(actions)
        if is_catch_all:
            bucket["catch_all_found"] = True
            if is_deny:
                bucket["catch_all_denied"] = True
            bucket["details"].append(
                {
                    "rule_name": rule_name,
                    "status": row.get("Status"),
                    "deny": is_deny,
                    "deny_path": deny_path,
                }
            )

    missing_or_not_deny = []
    passing = []
    for policy_name, result in policy_map.items():
        if result["catch_all_found"] and result["catch_all_denied"]:
            passing.append(policy_name)
        else:
            missing_or_not_deny.append(
                {
                    "policy": policy_name,
                    "issue": "Catch-all/default rule not found or not set to deny",
                    "details": result["details"],
                }
            )

    if not policy_map:
        validations.append(_validation(
            "App Sign-On Policy Catch-All Deny",
            "Info",
            "No authentication/app sign-on policy rule data was available to validate catch-all deny posture.",
            severity="High",
        ))
    elif missing_or_not_deny:
        validations.append(_validation(
            "App Sign-On Policy Catch-All Deny",
            "Warning",
            f"{len(missing_or_not_deny)} policy(s) may not have a catch-all/default deny rule configured.",
            [f"{item['policy']}: {item['issue']}" for item in missing_or_not_deny],
            severity="High",
        ))
    else:
        validations.append(_validation(
            "App Sign-On Policy Catch-All Deny",
            "Pass",
            f"Validated catch-all/default deny posture for {len(passing)} authentication/app sign-on policy(ies).",
            [f"{name}: catch-all/default deny detected" for name in passing[:8]],
            severity="High",
        ))

    # Validation 2: Session timeout > 2 hours in global session policies
    session_section = section_by_id.get("global-session-policies") or {}
    session_rows = session_section.get("rows") or []
    session_rule_rows = [r for r in session_rows if r.get("Entry Type") == "Rule"]
    timeout_violations = []
    for row in session_rule_rows:
        actions = _as_dict(row.get("Actions"))
        for finding in _extract_session_timeout_findings(actions, threshold_minutes=120):
            timeout_violations.append(
                {
                    "policy": row.get("Policy Name") or "Unknown Policy",
                    "rule": row.get("Rule Name") or "Unnamed Rule",
                    "path": finding["path"],
                    "minutes": finding["minutes"],
                    "raw": f"{finding['value']} ({finding['unit']})",
                }
            )

    if not session_rule_rows:
        validations.append(_validation(
            "Session Lifetime <= 2 Hours",
            "Info",
            "No global session policy rule data was available to validate session timeout settings.",
            severity="High",
        ))
    elif timeout_violations:
        policy_count = len({(v["policy"]) for v in timeout_violations})
        validations.append(_validation(
            "Session Lifetime <= 2 Hours",
            "Warning",
            f"Session lifetime duration is more than 2 hours on {policy_count} policy(s).",
            [
                f"{v['policy']} / {v['rule']}: {v['path']} = {v['raw']} (~{int(v['minutes'])} min)"
                for v in timeout_violations[:20]
            ],
            severity="High",
        ))
    else:
        validations.append(_validation(
            "Session Lifetime <= 2 Hours",
            "Pass",
            "No session timeout values above 2 hours were detected in global session policy rules.",
            severity="High",
        ))

    # Security notifications checks (High)
    sec_rows = (section_by_id.get("security-settings") or {}).get("rows") or []
    notification_checks = [
        ("Password Changed Notifications", "Password changed notification email"),
        ("Suspicious Activity Reporting for End Users", "Report suspicious activity via email"),
        ("New Sign-On Notifications", "New sign-on notification email"),
        ("Factor Enrollment Notifications", "Authenticator enrolled notification email"),
        ("Factor Reset Notifications", "Authenticator reset notification email"),
    ]
    for title, setting_name in notification_checks:
        value = _find_setting_value(sec_rows, setting_name)
        status = _status_from_boolish_enabled(value)
        if status == "Pass":
            summary = f"{title} are enabled."
        elif status == "Warning":
            summary = f"{title} are disabled."
        else:
            summary = f"{title} setting was not available in tenant response."
        validations.append(_validation(title, status, summary, severity="High"))

    # Weak password policies (Moderate)
    pwd_rows = (section_by_id.get("password-policies") or {}).get("rows") or []
    pwd_policy_rows = [r for r in pwd_rows if r.get("Entry Type") == "Policy"]
    weak_pwd = []
    for row in pwd_policy_rows:
        weaknesses = _password_policy_weaknesses(row)
        if weaknesses:
            weak_pwd.append((row.get("Name") or row.get("Policy Name") or "Unnamed Policy", weaknesses))
    if not pwd_policy_rows:
        validations.append(_validation(
            "Password Policy Strength",
            "Info",
            "No password policy data was available for password strength validation.",
            severity="Moderate",
        ))
    elif weak_pwd:
        validations.append(_validation(
            "Password Policy Strength",
            "Warning",
            f"Password policies for {len(weak_pwd)} policy(s) are weak.",
            [f"{name}: {', '.join(issues[:3])}" for name, issues in weak_pwd],
            severity="Moderate",
        ))
    else:
        validations.append(_validation(
            "Password Policy Strength",
            "Pass",
            "No weak password policy patterns were detected using current heuristics.",
            severity="Moderate",
        ))

    # Network zones blocklist presence (Moderate)
    zone_rows = (section_by_id.get("network-zones") or {}).get("rows") or []
    has_block_zone = any(
        "block" in str((z.get("Usage") or "")).lower() or "block" in str((z.get("Name") or "")).lower()
        for z in zone_rows
    )
    if not zone_rows:
        validations.append(_validation(
            "Blocklisted Network Zone Presence",
            "Info",
            "No network zone data was available to validate blocklisted zone configuration.",
            severity="Moderate",
        ))
    elif not has_block_zone:
        validations.append(_validation(
            "Blocklisted Network Zone Presence",
            "Warning",
            "Network Zones do not contain a block listed zone.",
            severity="Moderate",
        ))
    else:
        validations.append(_validation(
            "Blocklisted Network Zone Presence",
            "Pass",
            "At least one blocklisted network zone was detected.",
            severity="Moderate",
        ))

    # MFA enrollment policies: weaker factors + optional factors
    mfa_rows = (section_by_id.get("mfa-enrollment-policies") or {}).get("rows") or []
    mfa_policy_rows = [r for r in mfa_rows if r.get("Entry Type") == "Policy"]
    weak_factor_policies = []
    optional_factor_policies = []
    for row in mfa_policy_rows:
        name = row.get("Name") or row.get("Policy Name") or "Unnamed Policy"
        weak_factors = _mfa_policy_weak_factors(row)
        if weak_factors:
            weak_factor_policies.append((name, weak_factors))
        if _mfa_policy_has_optional_factors(row):
            optional_factor_policies.append(name)

    if not mfa_policy_rows:
        validations.append(_validation(
            "Weaker Factors in MFA Enrollment Policies",
            "Info",
            "No MFA enrollment policy data was available to evaluate weaker factor usage.",
            severity="High",
        ))
        validations.append(_validation(
            "Optional Factors in MFA Enrollment Policies",
            "Info",
            "No MFA enrollment policy data was available to evaluate optional factor enrollment.",
            severity="Moderate",
        ))
    else:
        validations.append(_validation(
            "Weaker Factors in MFA Enrollment Policies",
            "Warning" if weak_factor_policies else "Pass",
            (f"Weaker factors are set in {len(weak_factor_policies)} policies."
             if weak_factor_policies else "No weaker factors detected in MFA enrollment policy settings."),
            [f"{name}: {', '.join(factors)}" for name, factors in weak_factor_policies[:20]],
            severity="High",
        ))
        validations.append(_validation(
            "Optional Factors in MFA Enrollment Policies",
            "Warning" if optional_factor_policies else "Pass",
            (f"Factors are optional for {len(optional_factor_policies)} Factor Enrollment policies."
             if optional_factor_policies else "No optional factor enrollment settings detected in MFA enrollment policies."),
            optional_factor_policies[:20],
            severity="Moderate",
        ))

    # SAML apps disabled (High) using full app inventory (including inactive)
    all_apps = extra_context.get("all_apps") or []
    if not all_apps:
        validations.append(_validation(
            "SAML Authentication Supported but Disabled Apps",
            "Info",
            "No full application inventory was available to validate disabled SAML apps.",
            severity="High",
        ))
    else:
        disabled_saml = [
            app for app in all_apps
            if str(app.get("signOnMode") or "").upper() == "SAML_2_0"
            and str(app.get("status") or "").upper() != "ACTIVE"
        ]
        validations.append(_validation(
            "SAML Authentication Supported but Disabled Apps",
            "Warning" if disabled_saml else "Pass",
            (f"SAML authentication is supported but disabled for {len(disabled_saml)} apps."
             if disabled_saml else "No disabled SAML applications were detected."),
            [str(app.get("label") or app.get("name") or app.get("id")) for app in disabled_saml[:20]],
            severity="High",
        ))

    return validations


def _build_validation_summary(validations):
    summary = {
        "assessed": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "passed": 0,
        "pass_pct": 0,
    }
    for check in validations or []:
        summary["assessed"] += 1

        severity = str(check.get("severity") or "").strip().lower()
        if severity == "high":
            summary["high"] += 1
        elif severity in {"moderate", "medium"}:
            summary["medium"] += 1
        elif severity == "low":
            summary["low"] += 1

        if str(check.get("status") or "").strip().lower() == "pass":
            summary["passed"] += 1

    if summary["assessed"]:
        summary["pass_pct"] = round((summary["passed"] / summary["assessed"]) * 100)

    return summary


def _build_evaluate_summary(sections, domain, extra_context=None):
    section_by_id = _section_map(sections)
    total_sections = len(sections or [])
    populated_sections = sum(1 for s in (sections or []) if s.get("rows"))
    empty_sections = total_sections - populated_sections
    total_rows = sum(len(s.get("rows") or []) for s in (sections or []))

    readiness_groups = [
        {
            "name": "Core Access Controls",
            "section_ids": [
                "groups",
                "group-rules",
                "network-zones",
                "authenticators",
                "password-policies",
                "global-session-policies",
                "authentication-policies",
                "mfa-enrollment-policies",
            ],
        },
        {
            "name": "Identity Federation",
            "section_ids": [
                "identity-providers",
                "idp-discovery-policies",
                "profile-mappings",
            ],
        },
        {
            "name": "Platform Security & Settings",
            "section_ids": [
                "org-settings",
                "security-settings",
                "trusted-origins",
            ],
        },
        {
            "name": "Admin Delegation",
            "section_ids": [
                "custom-admin-roles",
                "resource-sets",
                "admin-assignments-users",
                "admin-assignments-groups",
                "admin-assignments-apps",
            ],
        },
        {
            "name": "Branding & End-User Experience",
            "section_ids": [
                "brand-settings",
                "brand-pages",
                "brand-email-templates",
            ],
        },
    ]

    group_results = []
    score_total = 0
    score_max = 0
    for group in readiness_groups:
        items = []
        present = 0
        for section_id in group["section_ids"]:
            section = section_by_id.get(section_id) or {}
            row_count = len(section.get("rows") or [])
            has_data = row_count > 0
            present += int(has_data)
            items.append(
                {
                    "id": section_id,
                    "title": section.get("title") or section_id,
                    "row_count": row_count,
                    "status": "Present" if has_data else "Not Found / Empty",
                }
            )
        total = len(group["section_ids"])
        pct = round((present / total) * 100) if total else 0
        score_total += present
        score_max += total
        if pct >= 85:
            risk = "Low"
        elif pct >= 60:
            risk = "Medium"
        else:
            risk = "High"
        group_results.append(
            {
                "name": group["name"],
                "present": present,
                "total": total,
                "pct": pct,
                "risk": risk,
                "items": items,
            }
        )

    overall_score = round((score_total / score_max) * 100) if score_max else 0
    if overall_score >= 85:
        readiness_band = "Ready"
    elif overall_score >= 65:
        readiness_band = "Needs Review"
    else:
        readiness_band = "High Attention"

    recommendations = []
    if empty_sections:
        recommendations.append(
            f"{empty_sections} snapshot sections returned no data. Verify API permissions and tenant feature availability."
        )
    if overall_score < 85:
        recommendations.append(
            "Run OktaCompare against the target environment before cutover to confirm policy, app, and IdP parity."
        )
    if not (section_by_id.get("custom-admin-roles") or {}).get("rows"):
        recommendations.append(
            "Review admin delegation model manually if custom admin roles/resource sets are not configured in this tenant."
        )
    if not (section_by_id.get("brand-pages") or {}).get("rows"):
        recommendations.append(
            "Validate end-user branding pages and email templates before go-live if branded experiences are in scope."
        )
    if not recommendations:
        recommendations.append("Tenant configuration coverage looks healthy. Proceed with detailed migration validation.")

    security_validations = _run_security_validations(sections or [], extra_context=extra_context)
    validation_summary = _build_validation_summary(security_validations)

    return {
        "domain": domain,
        "generated_at": datetime.now(ZoneInfo("Australia/Brisbane")).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "total_sections": total_sections,
        "populated_sections": populated_sections,
        "empty_sections": empty_sections,
        "total_rows": total_rows,
        "overall_score": overall_score,
        "readiness_band": readiness_band,
        "groups": group_results,
        "security_validations": security_validations,
        "validation_summary": validation_summary,
        "recommendations": recommendations,
    }


def _build_migration_plan(form_data):
    source_domain = form_data.get("source_domain", "").strip()
    target_domain = form_data.get("target_domain", "").strip()
    in_scope = {
        "groups": form_data.get("scope_groups") == "on",
        "apps": form_data.get("scope_apps") == "on",
        "policies": form_data.get("scope_policies") == "on",
        "idp": form_data.get("scope_idp") == "on",
        "branding": form_data.get("scope_branding") == "on",
        "admin": form_data.get("scope_admin") == "on",
    }

    scope_labels = []
    if in_scope["groups"]:
        scope_labels.append("Groups")
    if in_scope["apps"]:
        scope_labels.append("Applications")
    if in_scope["policies"]:
        scope_labels.append("Policies")
    if in_scope["idp"]:
        scope_labels.append("Identity Providers")
    if in_scope["branding"]:
        scope_labels.append("Branding")
    if in_scope["admin"]:
        scope_labels.append("Admin Delegation")

    phases = [
        {
            "phase": "1. Discovery & Baseline",
            "objective": "Capture current-state configuration and confirm migration scope.",
            "tasks": [
                f"Run OktaSnapshot for source tenant ({source_domain}) and export PDF/DOCX baseline.",
                "Document in-scope apps, policies, integrations, and business owners.",
                "Confirm cutover constraints, freeze windows, and rollback expectations.",
            ],
            "outputs": ["Source snapshot baseline", "Scope inventory", "Owner map"],
        },
        {
            "phase": "2. Target Readiness",
            "objective": "Prepare target tenant and validate prerequisite controls.",
            "tasks": [
                f"Run OktaSnapshot for target tenant ({target_domain}) to capture starting state.",
                "Validate org/security settings, trusted origins, authenticator posture, and admin access.",
                "Define target baseline and naming conventions for migrated objects.",
            ],
            "outputs": ["Target readiness checklist", "Target baseline snapshot"],
        },
        {
            "phase": "3. Build / Migration Execution",
            "objective": "Migrate in-scope configuration in controlled waves.",
            "tasks": [
                "Migrate by dependency order (foundational settings -> policies -> apps -> branding).",
                "Track exceptions, unsupported settings, and manual remediation items.",
                "Validate each wave with owners before proceeding.",
            ],
            "outputs": ["Wave tracker", "Issue log", "Validation sign-offs"],
        },
        {
            "phase": "4. Compare & Validate",
            "objective": "Confirm parity and identify residual drift before cutover.",
            "tasks": [
                f"Run OktaCompare between source ({source_domain}) and target ({target_domain}).",
                "Review Critical/Medium findings and remediate before cutover approval.",
                "Export CSV comparison report for approval and audit trail.",
            ],
            "outputs": ["Comparison report", "Remediation list", "Cutover readiness decision"],
        },
        {
            "phase": "5. Cutover & Hypercare",
            "objective": "Execute cutover safely and verify production behavior.",
            "tasks": [
                "Execute cutover checklist during approved maintenance window.",
                "Run post-cutover OktaCompare/OktaSnapshot validation and confirm no unexpected drift.",
                "Track incidents, user impact, and stabilization actions during hypercare.",
            ],
            "outputs": ["Cutover log", "Post-cutover validation", "Hypercare summary"],
        },
    ]

    risks = [
        {
            "name": "Policy/Rule Drift",
            "severity": "High" if in_scope["policies"] else "Medium",
            "mitigation": "Use OktaCompare before cutover and remediate Critical/Medium findings.",
        },
        {
            "name": "App Assignment / Integration Gaps",
            "severity": "High" if in_scope["apps"] else "Low",
            "mitigation": "Validate application owners, assignments, and test sign-on flows by wave.",
        },
        {
            "name": "Federation / IdP Differences",
            "severity": "High" if in_scope["idp"] else "Low",
            "mitigation": "Validate IdP discovery policies, profile mappings, and routing rules in test flows.",
        },
        {
            "name": "Branding / User Experience Regression",
            "severity": "Medium" if in_scope["branding"] else "Low",
            "mitigation": "Snapshot and validate brand pages, email templates, and sign-in UX before go-live.",
        },
        {
            "name": "Admin Access / Operational Readiness",
            "severity": "Medium" if in_scope["admin"] else "Low",
            "mitigation": "Confirm admin assignments, roles, and break-glass access in target tenant.",
        },
    ]

    workflow_name = "Extract Source -> Compare with Target -> Update Missing/Different"

    assumptions = [
        f"In scope: {', '.join(scope_labels) if scope_labels else 'No scopes selected (select at least one for a stronger plan).'}",
    ]

    return {
        "generated_at": datetime.now(ZoneInfo("Australia/Brisbane")).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "source_domain": source_domain,
        "target_domain": target_domain,
        "workflow_name": workflow_name,
        "in_scope": scope_labels,
        "phases": phases,
        "risks": risks,
        "assumptions": assumptions,
    }


def _build_group_sync_summary(source_groups, target_groups):
    source_groups = [g for g in (source_groups or []) if str(g.get("type") or "").upper() == "OKTA_GROUP"]
    target_groups = [g for g in (target_groups or []) if str(g.get("type") or "").upper() == "OKTA_GROUP"]

    src_by_name = {((g.get("profile") or {}).get("name") or ""): g for g in source_groups if (g.get("profile") or {}).get("name")}
    tgt_by_name = {((g.get("profile") or {}).get("name") or ""): g for g in target_groups if (g.get("profile") or {}).get("name")}

    missing = []
    different = []
    matched = 0
    extra = 0
    all_groups = []

    for name, src in src_by_name.items():
        src_profile = src.get("profile") or {}
        src_desc = src_profile.get("description") or ""
        tgt = tgt_by_name.get(name)
        if not tgt:
            missing.append({
                "name": name,
                "description": src_desc,
            })
            all_groups.append({
                "name": name,
                "source_description": src_desc,
                "target_description": "",
                "status": "Missing in Target",
            })
            continue
        tgt_profile = tgt.get("profile") or {}
        tgt_desc = tgt_profile.get("description") or ""
        if (src_desc or "") != (tgt_desc or ""):
            different.append({
                "name": name,
                "source_description": src_desc,
                "target_description": tgt_desc,
                "target_id": tgt.get("id"),
            })
            all_groups.append({
                "name": name,
                "source_description": src_desc,
                "target_description": tgt_desc,
                "status": "Different",
            })
        else:
            matched += 1
            all_groups.append({
                "name": name,
                "source_description": src_desc,
                "target_description": tgt_desc,
                "status": "Match",
            })

    for name in tgt_by_name:
        if name not in src_by_name:
            extra += 1
            tgt_desc = ((tgt_by_name.get(name) or {}).get("profile") or {}).get("description") or ""
            all_groups.append({
                "name": name,
                "source_description": "",
                "target_description": tgt_desc,
                "status": "Extra in Target",
            })

    all_groups.sort(key=lambda g: ((g.get("name") or "").lower(), g.get("status") or ""))

    return {
        "source_count": len(src_by_name),
        "target_count": len(tgt_by_name),
        "missing": missing,
        "different": different,
        "all_groups": all_groups,
        "matched_count": matched,
        "extra_count": extra,
        "pending_count": len(missing) + len(different),
    }


def _okta_headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _create_group(domain, api_token, name, description=""):
    url = f"{_ensure_https_domain(domain).rstrip('/')}/api/v1/groups"
    payload = {"profile": {"name": name, "description": description or ""}}
    return requests.post(url, headers=_okta_headers(api_token), json=payload, timeout=30)


def _update_group_description(domain, api_token, group_id, name, description=""):
    url = f"{_ensure_https_domain(domain).rstrip('/')}/api/v1/groups/{group_id}"
    payload = {"profile": {"name": name, "description": description or ""}}
    return requests.put(url, headers=_okta_headers(api_token), json=payload, timeout=30)


def _oktaevaluate_csv_bytes(evaluation):
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["What Was Checked", "Result", "Severity", "Summary", "Details"],
    )
    writer.writeheader()
    for check in (evaluation or {}).get("security_validations", []) or []:
        writer.writerow(
            {
                "What Was Checked": check.get("title", ""),
                "Result": check.get("status", ""),
                "Severity": check.get("severity", ""),
                "Summary": check.get("summary", ""),
                "Details": " | ".join([str(i) for i in (check.get("items") or [])]),
            }
        )
    return output.getvalue().encode("utf-8")


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
        logger.info("Collecting input values.")
        envA_domain = request.form.get("envA_domain", "").strip()
        envA_token  = request.form.get("envA_token", "").strip()
        envB_domain = request.form.get("envB_domain", "").strip()
        envB_token  = request.form.get("envB_token", "").strip()

        if not all([envA_domain, envA_token, envB_domain, envB_token]):
            logger.warning("Missing required comparison inputs.")
            return render_template(
                "oktacompare_error.html",
                title="Missing Required Input",
                message="Please provide Env A and Env B domains and API tokens.",
            ), 400


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
        # ENTITY RISK POLICIES
        # ===================================================
        logger.info("Comparing entity risk policies.")
        entity_risk_diffs, entity_risk_matches_raw = compare_entity_risk_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )
        entity_risk_matches_display = [
            {
                "Category": m["Category"], "Object": m["Object"], "Attribute": m["Attribute"],
                "Env A Value": m["Value"], "Env B Value": m["Value"], "Difference Type": "Match",
                "Impact": "", "Recommended Action": "", "Priority": "🟢 Match"
            } for m in entity_risk_matches_raw
        ]
        entity_risk_df = pd.DataFrame(entity_risk_diffs + entity_risk_matches_display)
        entity_risk_summary_counts = pd.DataFrame(entity_risk_diffs)["Priority"].value_counts().to_dict() if entity_risk_diffs else {}
        entity_risk_total_diff = len(entity_risk_diffs)
        logger.info("Entity risk policies comparison complete: diffs=%s matches=%s", len(entity_risk_diffs), len(entity_risk_matches_raw))

        # ===================================================
        # IDENTITY THREAT PROTECTION POLICIES
        # ===================================================
        logger.info("Comparing identity threat protection policies.")
        post_auth_diffs, post_auth_matches_raw = compare_post_auth_session_policies(
            envA_domain, envA_token,
            envB_domain, envB_token
        )
        post_auth_matches_display = [
            {
                "Category": m["Category"], "Object": m["Object"], "Attribute": m["Attribute"],
                "Env A Value": m["Value"], "Env B Value": m["Value"], "Difference Type": "Match",
                "Impact": "", "Recommended Action": "", "Priority": "🟢 Match"
            } for m in post_auth_matches_raw
        ]
        post_auth_df = pd.DataFrame(post_auth_diffs + post_auth_matches_display)
        post_auth_summary_counts = pd.DataFrame(post_auth_diffs)["Priority"].value_counts().to_dict() if post_auth_diffs else {}
        post_auth_total_diff = len(post_auth_diffs)
        logger.info("Identity threat protection policies comparison complete: diffs=%s matches=%s", len(post_auth_diffs), len(post_auth_matches_raw))

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
        # EVENT HOOKS
        # ===================================================
        logger.info("Comparing event hooks.")
        event_hook_diffs, event_hook_matches_raw = compare_event_hooks(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        event_hook_matches_display = [
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
            } for m in event_hook_matches_raw
        ]

        event_hook_df = pd.DataFrame(event_hook_diffs + event_hook_matches_display)
        event_hook_summary_counts = (
            pd.DataFrame(event_hook_diffs)["Priority"].value_counts().to_dict() if event_hook_diffs else {}
        )
        event_hook_total_diff = len(event_hook_diffs)
        logger.info(
            "Event hooks comparison complete: diffs=%s matches=%s",
            len(event_hook_diffs),
            len(event_hook_matches_raw),
        )

        # ===================================================
        # INLINE HOOKS
        # ===================================================
        logger.info("Comparing inline hooks.")
        inline_hook_diffs, inline_hook_matches_raw = compare_inline_hooks(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        inline_hook_matches_display = [
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
            } for m in inline_hook_matches_raw
        ]

        inline_hook_df = pd.DataFrame(inline_hook_diffs + inline_hook_matches_display)
        inline_hook_summary_counts = (
            pd.DataFrame(inline_hook_diffs)["Priority"].value_counts().to_dict() if inline_hook_diffs else {}
        )
        inline_hook_total_diff = len(inline_hook_diffs)
        logger.info(
            "Inline hooks comparison complete: diffs=%s matches=%s",
            len(inline_hook_diffs),
            len(inline_hook_matches_raw),
        )

        # ===================================================
        # ACCESS CONTROLS - ATTACK PROTECTION
        # ===================================================
        logger.info("Comparing attack protection controls.")
        attack_protection_diffs, attack_protection_matches_raw = compare_attack_protection(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        attack_protection_matches_display = [
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
            } for m in attack_protection_matches_raw
        ]

        attack_protection_df = pd.DataFrame(attack_protection_diffs + attack_protection_matches_display)
        attack_protection_summary_counts = (
            pd.DataFrame(attack_protection_diffs)["Priority"].value_counts().to_dict() if attack_protection_diffs else {}
        )
        attack_protection_total_diff = len(attack_protection_diffs)
        logger.info(
            "Attack protection comparison complete: diffs=%s matches=%s",
            len(attack_protection_diffs),
            len(attack_protection_matches_raw),
        )

        # ===================================================
        # GROUP PUSH MAPPINGS
        # ===================================================
        logger.info("Comparing group push mappings.")
        group_push_diffs, group_push_matches_raw = compare_group_push_mappings(
            envA_domain, envA_token,
            envB_domain, envB_token
        )

        group_push_matches_display = [
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
            } for m in group_push_matches_raw
        ]

        group_push_df = pd.DataFrame(group_push_diffs + group_push_matches_display)
        group_push_summary_counts = (
            pd.DataFrame(group_push_diffs)["Priority"].value_counts().to_dict() if group_push_diffs else {}
        )
        group_push_total_diff = len(group_push_diffs)
        logger.info(
            "Group push mappings comparison complete: diffs=%s matches=%s",
            len(group_push_diffs),
            len(group_push_matches_raw),
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
            + entity_risk_diffs
            + post_auth_diffs
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
            + event_hook_diffs
            + inline_hook_diffs
            + attack_protection_diffs
            + group_push_diffs
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
            + entity_risk_matches_raw
            + post_auth_matches_raw
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
            + event_hook_matches_raw
            + inline_hook_matches_raw
            + attack_protection_matches_raw
            + group_push_matches_raw
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

            # Entity Risk Policies
            entity_risk_df=entity_risk_df.to_dict(orient="records"),
            entity_risk_summary_counts=entity_risk_summary_counts,
            entity_risk_total_diff=entity_risk_total_diff,

            # Identity Threat Protection Policies
            post_auth_df=post_auth_df.to_dict(orient="records"),
            post_auth_summary_counts=post_auth_summary_counts,
            post_auth_total_diff=post_auth_total_diff,

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

            # Event Hooks
            event_hook_df=event_hook_df.to_dict(orient="records"),
            event_hook_summary_counts=event_hook_summary_counts,
            event_hook_total_diff=event_hook_total_diff,

            # Inline Hooks
            inline_hook_df=inline_hook_df.to_dict(orient="records"),
            inline_hook_summary_counts=inline_hook_summary_counts,
            inline_hook_total_diff=inline_hook_total_diff,

            # Access Controls - Attack Protection
            attack_protection_df=attack_protection_df.to_dict(orient="records"),
            attack_protection_summary_counts=attack_protection_summary_counts,
            attack_protection_total_diff=attack_protection_total_diff,

            # Group Push Mappings
            group_push_df=group_push_df.to_dict(orient="records"),
            group_push_summary_counts=group_push_summary_counts,
            group_push_total_diff=group_push_total_diff,

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


@app.errorhandler(404)
def handle_not_found(error):
    logger.warning("Route not found: %s %s", request.method, request.path)
    return render_template(
        "oktacompare_error.html",
        title="Page Not Found",
        message="The requested page does not exist. Please check the URL and try again.",
    ), 404


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        logger.warning("HTTP error: %s %s", error.code, error)
        return render_template(
            "oktacompare_error.html",
            title=f"Request Error ({error.code})",
            message=error.description or "The request could not be completed.",
        ), error.code
    logger.exception("Unhandled error: %s", error)
    return render_template(
        "oktacompare_error.html",
        title="Something Went Wrong",
        message="We hit an unexpected error while building the report. Please retry.",
    ), 500

@app.route("/snapshot", methods=["GET"])
def oktasnapshot_form():
    logger.info("Rendering OktaSnapshot form.")
    return render_template("oktasnapshot_form.html")


@app.route("/snapshot", methods=["POST"])
def oktasnapshot_generate():
    domain = (request.form.get("domain") or "").strip()
    api_token = (request.form.get("api_token") or "").strip()

    if not domain or not api_token:
        logger.warning("Missing required OktaSnapshot inputs.")
        return render_template(
            "oktacompare_error.html",
            title="Missing Required Input",
            message="Please provide the Okta domain and API token for OktaSnapshot.",
        ), 400

    logger.info("Generating OktaSnapshot guide for %s.", domain)
    sections, export_rows = build_oktasnapshot_guide(domain, api_token)
    OKTASNAPSHOT_EXPORT["rows"] = export_rows
    OKTASNAPSHOT_GUIDE["sections"] = sections
    OKTASNAPSHOT_GUIDE["domain"] = domain

    return redirect(url_for("oktasnapshot_guide"))


@app.route("/snapshot/guide", methods=["GET"])
def oktasnapshot_guide():
    sections = OKTASNAPSHOT_GUIDE.get("sections") or []
    domain = OKTASNAPSHOT_GUIDE.get("domain") or ""
    return render_template(
        "oktasnapshot_report.html",
        guide_sections=sections,
        guide_domain=domain,
        guide_generated_at=datetime.now(ZoneInfo("Australia/Brisbane")).strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
    )


@app.route("/snapshot/export", methods=["GET"])
def oktasnapshot_export():
    sections = OKTASNAPSHOT_GUIDE.get("sections") or []
    domain = OKTASNAPSHOT_GUIDE.get("domain") or ""
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
        "oktasnapshot_pdf.html",
        guide_sections=sections,
        guide_domain=domain,
    )
    pdf = HTML(string=html).write_pdf()
    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="oktasnapshot_guide.pdf",
    )


def _docx_cell_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, indent=2, default=str)
    return str(value)


def _docx_set_cell_shading(cell, fill):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), fill)
    cell._tc.get_or_add_tcPr().append(shading)


def _docx_style_header_cell(cell, text, fill="D9E2F3"):
    from docx.shared import RGBColor

    cell.text = text
    for paragraph in cell.paragraphs:
        for run in paragraph.runs:
            run.bold = True
            run.font.color.rgb = RGBColor(31, 41, 55)
    _docx_set_cell_shading(cell, fill)


def _docx_stripe_row(table, row_idx, fill):
    for cell in table.rows[row_idx].cells:
        _docx_set_cell_shading(cell, fill)


def _docx_set_table_borders(table):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tbl = table._tbl
    tbl_pr = tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = OxmlElement(f"w:{edge}")
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), "4")
        element.set(qn("w:space"), "0")
        element.set(qn("w:color"), "D9DDE5")
        borders.append(element)
    tbl_pr.append(borders)


@app.route("/snapshot/export/docx", methods=["GET"])
def oktasnapshot_export_docx():
    sections = OKTASNAPSHOT_GUIDE.get("sections") or []
    domain = OKTASNAPSHOT_GUIDE.get("domain") or ""
    if not sections:
        logger.warning("No OktaSnapshot guide data found for Word export.")
    try:
        from docx import Document
        from docx.shared import RGBColor
    except Exception:
        logger.exception("python-docx not available for Word export.")
        return render_template(
            "oktacompare_error.html",
            title="Word Export Unavailable",
            message="Word export requires python-docx. Please install it and retry.",
        ), 500

    document = Document()
    document.add_heading("OktaSnapshot Configuration", level=0)
    document.add_paragraph(f"Generated for {domain}.")

    for style_name, color in (
        ("Normal", RGBColor(0, 0, 0)),
        ("Heading 1", RGBColor(31, 41, 55)),
        ("Heading 2", RGBColor(31, 41, 55)),
    ):
        try:
            style = document.styles[style_name]
        except KeyError:
            style = None
        if style:
            style.font.color.rgb = color

    for section in sections:
        document.add_heading(section.get("title") or section.get("id") or "Section", level=1)
        rows = section.get("rows") or []
        if not rows:
            document.add_paragraph("No data available.")
            continue

        if section.get("id") in ["org-settings", "security-settings"]:
            table = document.add_table(rows=len(rows) + 1, cols=2)
            table.style = "Light Shading Accent 1"
            _docx_set_table_borders(table)
            _docx_style_header_cell(table.cell(0, 0), "Setting")
            _docx_style_header_cell(table.cell(0, 1), "Value")
            for idx, row in enumerate(rows, start=1):
                table.cell(idx, 0).text = _docx_cell_value(row.get("Setting", ""))
                table.cell(idx, 1).text = _docx_cell_value(row.get("Value", ""))
                _docx_stripe_row(table, idx, "EFF5FF" if idx % 2 == 1 else "FFFFFF")
        else:
            for row in rows:
                columns = row.keys() if section.get("id") == "applications" else section.get("columns") or row.keys()
                table = document.add_table(rows=len(columns) + 1, cols=2)
                table.style = "Light Shading Accent 1"
                _docx_set_table_borders(table)
                _docx_style_header_cell(table.cell(0, 0), "Field")
                _docx_style_header_cell(table.cell(0, 1), "Value")
                for idx, col in enumerate(columns, start=1):
                    table.cell(idx, 0).text = _docx_cell_value(col)
                    table.cell(idx, 1).text = _docx_cell_value(row.get(col, ""))
                    _docx_stripe_row(table, idx, "EFF5FF" if idx % 2 == 1 else "FFFFFF")

        document.add_paragraph("")

    output = io.BytesIO()
    document.save(output)
    output.seek(0)
    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name="oktasnapshot_guide.docx",
    )


@app.route("/evaluate", methods=["GET", "POST"])
@app.route("/validate", methods=["GET", "POST"])
def okta_evaluate():
    if request.method == "POST":
        domain = (request.form.get("domain") or "").strip()
        api_token = (request.form.get("api_token") or "").strip()
        if not domain or not api_token:
            return render_template(
                "okta_evaluate.html",
                form_error="Please provide the Okta domain and API token before running evaluation.",
                form_values={"domain": domain},
            ), 400

        logger.info("Running OktaEvaluate readiness assessment for %s.", domain)
        sections, _ = build_oktasnapshot_guide(domain, api_token)
        all_apps = get_all_applications(domain, api_token, limit=200) or []
        result = _build_evaluate_summary(sections, domain, extra_context={"all_apps": all_apps})
        OKTAEVALUATE_EXPORT["evaluation"] = result
        return render_template(
            "okta_evaluate.html",
            evaluation=result,
            form_values={"domain": domain},
        )

    logger.info("Rendering OktaEvaluate page.")
    return render_template("okta_evaluate.html", form_values={})


@app.route("/evaluate/export/csv", methods=["GET"])
def okta_evaluate_export_csv():
    evaluation = OKTAEVALUATE_EXPORT.get("evaluation")
    if not evaluation:
        logger.warning("No OktaEvaluate data found for CSV export.")
    return send_file(
        io.BytesIO(_oktaevaluate_csv_bytes(evaluation or {})),
        mimetype="text/csv",
        as_attachment=True,
        download_name="oktaevaluate_security_validation_report.csv",
    )


@app.route("/evaluate/export/pdf", methods=["GET"])
def okta_evaluate_export_pdf():
    evaluation = OKTAEVALUATE_EXPORT.get("evaluation")
    if not evaluation:
        logger.warning("No OktaEvaluate data found for PDF export.")
    try:
        from weasyprint import HTML
    except Exception:
        logger.exception("WeasyPrint not available for OktaEvaluate PDF export.")
        return render_template(
            "oktacompare_error.html",
            title="PDF Export Unavailable",
            message="PDF export requires WeasyPrint. Please install it and retry.",
        ), 500

    html = render_template(
        "okta_evaluate_pdf.html",
        evaluation=evaluation or {
            "domain": "",
            "generated_at": "",
            "security_validations": [],
            "overall_score": "",
            "readiness_band": "",
        },
    )
    pdf = HTML(string=html).write_pdf()
    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name="oktaevaluate_security_validation_report.pdf",
    )


@app.route("/migrate", methods=["GET", "POST"])
def okta_migrate():
    if request.method == "POST":
        source_domain = (request.form.get("source_domain") or "").strip()
        source_token = (request.form.get("source_token") or "").strip()
        target_domain = (request.form.get("target_domain") or "").strip()
        target_token = (request.form.get("target_token") or "").strip()
        if not all([source_domain, source_token, target_domain, target_token]):
            return render_template(
                "okta_migrate.html",
                form_error="Please provide source and target domains and API tokens to generate a migration plan.",
                form_values=request.form,
            ), 400

        logger.info("Generating OktaMigrate plan for %s -> %s.", source_domain, target_domain)
        plan = _build_migration_plan(request.form)
        group_sync = None
        if request.form.get("scope_groups") == "on":
            source_groups = get_groups(source_domain, source_token) or []
            target_groups = get_groups(target_domain, target_token) or []
            group_sync = _build_group_sync_summary(source_groups, target_groups)
            OKTAMIGRATE_EXPORT["group_sync"] = group_sync
            OKTAMIGRATE_EXPORT["source_domain"] = source_domain
            OKTAMIGRATE_EXPORT["source_token"] = source_token
            OKTAMIGRATE_EXPORT["target_domain"] = target_domain
            OKTAMIGRATE_EXPORT["target_token"] = target_token
        else:
            OKTAMIGRATE_EXPORT["group_sync"] = None
            OKTAMIGRATE_EXPORT["source_domain"] = ""
            OKTAMIGRATE_EXPORT["source_token"] = ""
            OKTAMIGRATE_EXPORT["target_domain"] = ""
            OKTAMIGRATE_EXPORT["target_token"] = ""
        plan["group_sync"] = group_sync
        OKTAMIGRATE_EXPORT["plan"] = plan
        return render_template(
            "okta_migrate.html",
            migration_plan=plan,
            form_values=request.form,
        )

    logger.info("Rendering OktaMigrate page.")
    return render_template("okta_migrate.html", form_values={})


@app.route("/migrate/update/groups", methods=["POST"])
def okta_migrate_update_groups():
    plan = OKTAMIGRATE_EXPORT.get("plan")
    group_sync = OKTAMIGRATE_EXPORT.get("group_sync")
    source_domain = (OKTAMIGRATE_EXPORT.get("source_domain") or "").strip()
    source_token = (OKTAMIGRATE_EXPORT.get("source_token") or "").strip()
    target_domain = (OKTAMIGRATE_EXPORT.get("target_domain") or "").strip()
    target_token = (OKTAMIGRATE_EXPORT.get("target_token") or "").strip()
    if not plan or not group_sync or not source_domain or not source_token or not target_domain or not target_token:
        return render_template(
            "okta_migrate.html",
            form_error="No migration group comparison context found. Generate the migration plan again.",
            form_values={},
        ), 400

    selected_names = set([n for n in request.form.getlist("selected_group_names") if n])
    if not selected_names:
        plan = dict(plan)
        plan["group_sync"] = group_sync
        plan["group_update_result"] = {
            "created": [],
            "updated": [],
            "errors": ["No groups selected. Select one or more missing groups and click Migrate."],
        }
        return render_template("okta_migrate.html", migration_plan=plan, form_values={}), 400

    action_result = {"created": [], "updated": [], "errors": []}

    missing_by_name = {item.get("name"): item for item in (group_sync.get("missing", []) or [])}
    for name in selected_names:
        item = missing_by_name.get(name)
        if not item:
            action_result["errors"].append(f"Group '{name}' is not currently marked as missing in target.")
            continue
        # Missing list is already filtered to OKTA_GROUP entries via _build_group_sync_summary.
        resp = _create_group(target_domain, target_token, item.get("name"), item.get("description"))
        if resp.status_code in (200, 201):
            action_result["created"].append(item.get("name"))
        else:
            action_result["errors"].append(f"Create {item.get('name')}: {resp.status_code} {resp.text[:200]}")

    # Refresh comparison after applying updates
    source_groups = get_groups(source_domain, source_token) or []
    target_groups = get_groups(target_domain, target_token) or []
    refreshed_group_sync = _build_group_sync_summary(source_groups, target_groups)
    plan = dict(plan)
    plan["group_sync"] = refreshed_group_sync
    plan["group_update_result"] = action_result
    OKTAMIGRATE_EXPORT["plan"] = plan
    OKTAMIGRATE_EXPORT["group_sync"] = refreshed_group_sync

    return render_template(
        "okta_migrate.html",
        migration_plan=plan,
        form_values={},
    )


@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory("templates/static", filename)


# ---------------------------------------------------
# Run App
# ---------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting OktaCompare Flask app.")
    app.run(host="0.0.0.0", debug=False, port=5000)
