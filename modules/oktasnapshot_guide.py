import logging

from scripts.oktasnapshot_org_settings import get_org_settings
from scripts.oktasnapshot_security_settings import get_security_settings
from scripts.oktasnapshot_groups import get_groups_view
from scripts.oktasnapshot_group_rules import get_group_rules_view
from scripts.oktasnapshot_network_zones import get_network_zones
from scripts.oktasnapshot_identity_providers import get_identity_providers
from scripts.oktasnapshot_authenticators import get_authenticators_view
from scripts.oktasnapshot_authorization_server_settings import get_authorization_server_settings_view
from scripts.oktasnapshot_authorization_server_access_policies import get_authorization_server_access_policies_view
from scripts.oktasnapshot_applications import get_applications
from scripts.oktasnapshot_password_policies import get_password_policies
from scripts.oktasnapshot_global_session_policies import get_global_session_policies
from scripts.oktasnapshot_authentication_policies import get_authentication_policies
from scripts.oktasnapshot_mfa_enrollment_policies import get_mfa_enrollment_policies
from scripts.oktasnapshot_idp_discovery_policies import get_idp_discovery_policies_view
from scripts.oktasnapshot_profile_enrollment_policies import get_profile_enrollment_policies_view
from scripts.oktasnapshot_brand_settings import get_brand_settings_view
from scripts.oktasnapshot_brand_pages import get_brand_pages_view
from scripts.oktasnapshot_brand_email_templates import get_brand_email_templates_view
from scripts.oktasnapshot_custom_admin_roles import get_custom_admin_roles_view
from scripts.oktasnapshot_resource_sets import get_resource_sets_view
from scripts.oktasnapshot_admin_assignments import get_admin_assignments_view
from scripts.oktasnapshot_api_tokens import get_api_tokens_view
from scripts.oktasnapshot_realms import get_realms_view, get_realm_assignments_view
from scripts.oktasnapshot_profile_schema_user import get_profile_schema_user_view
from scripts.oktasnapshot_profile_mappings import get_profile_mappings_view
from scripts.oktasnapshot_trusted_origins import get_trusted_origins_view
from scripts.oktasnapshot_event_hooks import get_event_hooks_view
from scripts.oktasnapshot_inline_hooks import get_inline_hooks_view
from scripts.oktasnapshot_attack_protection import get_attack_protection_view
from scripts.oktasnapshot_group_push_mappings import get_group_push_mappings_view
from scripts.oktasnapshot_entity_risk_policies import get_entity_risk_policies_view
from scripts.oktasnapshot_post_auth_session_policies import get_post_auth_session_policies_view
from scripts.oktasnapshot_agents import get_agents_view

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


def build_oktasnapshot_guide(domain, api_token):
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
    event_hooks = get_event_hooks_view(domain, api_token) or []
    inline_hooks = get_inline_hooks_view(domain, api_token) or []
    attack_protection = get_attack_protection_view(domain, api_token) or []
    group_push_mappings = get_group_push_mappings_view(domain, api_token) or []
    entity_risk_policies, entity_risk_rules = get_entity_risk_policies_view(domain, api_token)
    post_auth_policies, post_auth_rules = get_post_auth_session_policies_view(domain, api_token)
    agents = get_agents_view(domain, api_token) or []

    authz_access_combined = []
    for row in authz_access_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        authz_access_combined.append(combined)
    for row in authz_access_policy_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        authz_access_combined.append(combined)

    password_combined = []
    for row in password_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        password_combined.append(combined)
    for row in password_policy_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        password_combined.append(combined)

    global_session_combined = []
    for row in global_session_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        global_session_combined.append(combined)
    for row in global_session_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        global_session_combined.append(combined)

    authentication_combined = []
    for row in authentication_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        authentication_combined.append(combined)
    for row in authentication_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        authentication_combined.append(combined)

    mfa_combined = []
    for row in mfa_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        mfa_combined.append(combined)
    for row in mfa_policy_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        mfa_combined.append(combined)

    idp_discovery_combined = []
    for row in idp_discovery_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        idp_discovery_combined.append(combined)
    for row in idp_discovery_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        idp_discovery_combined.append(combined)

    profile_enrollment_combined = []
    for row in profile_enrollment_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        profile_enrollment_combined.append(combined)

    entity_risk_combined = []
    for row in entity_risk_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        entity_risk_combined.append(combined)
    for row in entity_risk_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        entity_risk_combined.append(combined)

    post_auth_combined = []
    for row in post_auth_policies:
        combined = dict(row)
        combined["Entry Type"] = "Policy"
        post_auth_combined.append(combined)
    for row in post_auth_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        post_auth_combined.append(combined)
    for row in profile_enrollment_rules:
        combined = dict(row)
        combined["Entry Type"] = "Rule"
        profile_enrollment_combined.append(combined)

    resource_sets_combined = []
    for row in resource_sets:
        combined = dict(row)
        combined["Entry Type"] = "Resource Set"
        resource_sets_combined.append(combined)
    for row in resource_set_resources:
        combined = dict(row)
        combined["Entry Type"] = "Resource"
        resource_sets_combined.append(combined)
    for row in resource_set_bindings:
        combined = dict(row)
        combined["Entry Type"] = "Binding"
        resource_sets_combined.append(combined)

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
        _section("authz-access-policies", "Authorization Servers - Access Policies", authz_access_combined),
        _section("applications", "Applications", applications),
        _section("password-policies", "Password Policies", password_combined),
        _section("global-session-policies", "Global Session Policies", global_session_combined),
        _section("authentication-policies", "Authentication Policies", authentication_combined),
        _section("mfa-enrollment-policies", "MFA Enrollment Policies", mfa_combined),
        _section("idp-discovery-policies", "IDP Discovery Policies", idp_discovery_combined),
        _section("profile-enrollment-policies", "Profile Enrollment Policies", profile_enrollment_combined),
        _section("entity-risk-policies", "Entity Risk Policies", entity_risk_combined),
        _section("post-auth-session-policies", "Identity Threat Protection Policies", post_auth_combined),
        _section("brand-settings", "Brand Settings", brand_settings),
        _section("brand-pages", "Brand Pages", brand_pages),
        _section("brand-email-templates", "Brand Email Templates", brand_email_templates),
        _section("custom-admin-roles", "Custom Admin Roles", custom_admin_roles),
        _section("resource-sets", "Resource Sets", resource_sets_combined),
        _section("admin-assignments-users", "Admin Assignments - Users", admin_users),
        _section("admin-assignments-groups", "Admin Assignments - Groups", admin_groups),
        _section("admin-assignments-apps", "Admin Assignments - Apps", admin_apps),
        _section("api-tokens", "API Tokens", api_tokens),
        _section("realms", "Realms", realms),
        _section("realm-assignments", "Realm Assignments", realm_assignments),
        _section("profile-schema-user", "Profile Schema - User", profile_schema_user),
        _section("profile-mappings", "Profile Mappings", profile_mappings),
        _section("trusted-origins", "Trusted Origins", trusted_origins),
        _section("event-hooks", "Event Hooks", event_hooks),
        _section("inline-hooks", "Inline Hooks", inline_hooks),
        _section("attack-protection", "Access Controls - Attack Protection", attack_protection),
        _section("group-push-mappings", "Group Push Mappings", group_push_mappings),
        _section("agents", "Agents", agents),
    ]

    export_rows = _export_rows_from_sections(sections)
    return sections, export_rows
