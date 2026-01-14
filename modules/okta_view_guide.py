import logging

from scripts.okta_view_org_settings import get_org_settings
from scripts.okta_view_security_settings import get_security_settings
from scripts.okta_view_groups import get_groups_view
from scripts.okta_view_group_rules import get_group_rules_view
from scripts.okta_view_network_zones import get_network_zones
from scripts.okta_view_identity_providers import get_identity_providers
from scripts.okta_view_authenticators import get_authenticators_view
from scripts.okta_view_authorization_server_settings import get_authorization_server_settings_view
from scripts.okta_view_authorization_server_access_policies import get_authorization_server_access_policies_view
from scripts.okta_view_applications import get_applications
from scripts.okta_view_password_policies import get_password_policies
from scripts.okta_view_global_session_policies import get_global_session_policies
from scripts.okta_view_authentication_policies import get_authentication_policies
from scripts.okta_view_mfa_enrollment_policies import get_mfa_enrollment_policies
from scripts.okta_view_idp_discovery_policies import get_idp_discovery_policies_view
from scripts.okta_view_profile_enrollment_policies import get_profile_enrollment_policies_view
from scripts.okta_view_brand_settings import get_brand_settings_view
from scripts.okta_view_brand_pages import get_brand_pages_view
from scripts.okta_view_brand_email_templates import get_brand_email_templates_view
from scripts.okta_view_custom_admin_roles import get_custom_admin_roles_view
from scripts.okta_view_resource_sets import get_resource_sets_view
from scripts.okta_view_admin_assignments import get_admin_assignments_view
from scripts.okta_view_api_tokens import get_api_tokens_view
from scripts.okta_view_realms import get_realms_view, get_realm_assignments_view
from scripts.okta_view_profile_schema_user import get_profile_schema_user_view
from scripts.okta_view_profile_mappings import get_profile_mappings_view
from scripts.okta_view_trusted_origins import get_trusted_origins_view

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _key_value_rows(values):
    rows = []
    for key, value in (values or {}).items():
        rows.append({
            "Setting": key,
            "Value": value,
        })
    return rows


def _section(section_id, title, rows, description=None):
    return {
        "id": section_id,
        "title": title,
        "description": description or "",
        "rows": rows or [],
        "columns": list((rows or [{}])[0].keys()) if rows else [],
    }


def _row_identifier(row):
    for key in (
        "Application Name",
        "Rule Name",
        "Policy Name",
        "Name",
        "ID",
        "Rule ID",
        "Policy ID",
        "Setting",
    ):
        value = row.get(key)
        if value:
            return str(value)
    return "Item"


def _export_rows_from_sections(sections):
    export_rows = []
    identifier_keys = {"Setting"}
    for section in sections:
        for row in section.get("rows", []):
            item = _row_identifier(row)
            for field, value in row.items():
                if field in identifier_keys and str(value) == item:
                    continue
                export_rows.append({
                    "Section": section.get("title"),
                    "Item": item,
                    "Field": field,
                    "Value": value,
                })
    return export_rows


def build_okta_view_guide(domain, api_token):
    logger.info("Building OktaView guide for %s.", domain)

    org_settings = get_org_settings(domain, api_token) or {}
    security_settings = get_security_settings(domain, api_token) or []
    groups = get_groups_view(domain, api_token) or []
    group_rules = get_group_rules_view(domain, api_token) or []
    network_zones = get_network_zones(domain, api_token) or []
    identity_providers = get_identity_providers(domain, api_token) or []
    authenticators = get_authenticators_view(domain, api_token) or []
    authz_servers, authz_claims, authz_scopes = get_authorization_server_settings_view(domain, api_token)
    authz_access_policies, authz_access_policy_rules = get_authorization_server_access_policies_view(
        domain, api_token
    )
    applications = get_applications(domain, api_token) or []
    password_policies, password_policy_rules = get_password_policies(domain, api_token)
    global_session_policies, global_session_rules = get_global_session_policies(domain, api_token)
    authentication_policies, authentication_rules = get_authentication_policies(domain, api_token)
    mfa_policies, mfa_policy_rules = get_mfa_enrollment_policies(domain, api_token)
    idp_discovery_policies, idp_discovery_rules = get_idp_discovery_policies_view(domain, api_token)
    profile_enrollment_policies, profile_enrollment_rules = get_profile_enrollment_policies_view(domain, api_token)
    brand_settings = get_brand_settings_view(domain, api_token) or []
    brand_pages = get_brand_pages_view(domain, api_token) or []
    brand_email_templates = get_brand_email_templates_view(domain, api_token) or []
    custom_admin_roles = get_custom_admin_roles_view(domain, api_token) or []
    resource_sets, resource_set_resources, resource_set_bindings = get_resource_sets_view(domain, api_token)
    admin_users, admin_groups, admin_apps = get_admin_assignments_view(domain, api_token)
    api_tokens = get_api_tokens_view(domain, api_token) or []
    realms = get_realms_view(domain, api_token) or []
    realm_assignments = get_realm_assignments_view(domain, api_token) or []
    profile_schema_user = get_profile_schema_user_view(domain, api_token) or []
    profile_mappings = get_profile_mappings_view(domain, api_token) or []
    trusted_origins = get_trusted_origins_view(domain, api_token) or []

    sections = [
        _section("org-settings", "Organization Settings", _key_value_rows(org_settings)),
        _section("security-settings", "Security General Settings", security_settings),
        _section("groups", "Groups", groups),
        _section("group-rules", "Group Rules", group_rules),
        _section("network-zones", "Network Zones", network_zones),
        _section("identity-providers", "Identity Providers", identity_providers),
        _section("authenticators", "Authenticators", authenticators),
        _section("authz-servers", "Authorization Servers - Settings", authz_servers),
        _section("authz-claims", "Authorization Server Claims", authz_claims),
        _section("authz-scopes", "Authorization Server Scopes", authz_scopes),
        _section("authz-access-policies", "Authorization Servers - Access Policies", authz_access_policies),
        _section("authz-access-policy-rules", "Authorization Server Access Policy Rules", authz_access_policy_rules),
        _section("applications", "Applications", applications),
        _section("password-policies", "Password Policies", password_policies),
        _section("password-policy-rules", "Password Policy Rules", password_policy_rules),
        _section("global-session-policies", "Global Session Policies", global_session_policies),
        _section("global-session-policy-rules", "Global Session Policy Rules", global_session_rules),
        _section("authentication-policies", "Authentication Policies", authentication_policies),
        _section("authentication-policy-rules", "Authentication Policy Rules", authentication_rules),
        _section("mfa-enrollment-policies", "MFA Enrollment Policies", mfa_policies),
        _section("mfa-enrollment-policy-rules", "MFA Enrollment Policy Rules", mfa_policy_rules),
        _section("idp-discovery-policies", "IDP Discovery Policies", idp_discovery_policies),
        _section("idp-discovery-policy-rules", "IDP Discovery Policy Rules", idp_discovery_rules),
        _section("profile-enrollment-policies", "Profile Enrollment Policies", profile_enrollment_policies),
        _section("profile-enrollment-policy-rules", "Profile Enrollment Policy Rules", profile_enrollment_rules),
        _section("brand-settings", "Brand Settings", brand_settings),
        _section("brand-pages", "Brand Pages", brand_pages),
        _section("brand-email-templates", "Brand Email Templates", brand_email_templates),
        _section("custom-admin-roles", "Custom Admin Roles", custom_admin_roles),
        _section("resource-sets", "Resource Sets", resource_sets),
        _section("resource-set-resources", "Resource Set Resources", resource_set_resources),
        _section("resource-set-bindings", "Resource Set Bindings", resource_set_bindings),
        _section("admin-assignments-users", "Admin Assignments - Users", admin_users),
        _section("admin-assignments-groups", "Admin Assignments - Groups", admin_groups),
        _section("admin-assignments-apps", "Admin Assignments - Apps", admin_apps),
        _section("api-tokens", "API Tokens", api_tokens),
        _section("realms", "Realms", realms),
        _section("realm-assignments", "Realm Assignments", realm_assignments),
        _section("profile-schema-user", "Profile Schema - User", profile_schema_user),
        _section("profile-mappings", "Profile Mappings", profile_mappings),
        _section("trusted-origins", "Trusted Origins", trusted_origins),
    ]

    export_rows = _export_rows_from_sections(sections)
    return sections, export_rows
