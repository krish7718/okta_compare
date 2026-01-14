import logging

from scripts.extract_authorization_servers import (
    get_authorization_servers,
    get_authorization_server_policies,
    get_authorization_server_policy_rules,
)
from scripts.okta_view_utils import ensure_domain_str, get_json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_authorization_server_access_policies_view(domain_url, api_token):
    logger.info("Fetching authorization server access policies for OktaView.")
    base = ensure_domain_str(domain_url).rstrip("/")
    servers = get_authorization_servers(domain_url, api_token) or []
    policy_rows = []
    rule_rows = []
    app_cache = {}

    def _resolve_app_name(app_id):
        if not app_id:
            return app_id
        if app_id in app_cache:
            return app_cache[app_id]
        app = get_json(
            f"{base}/api/v1/apps/{app_id}",
            {"Authorization": f"SSWS {api_token}", "Accept": "application/json"},
            "Error fetching app for access policy",
        )
        name = ""
        if isinstance(app, dict):
            name = app.get("label") or app.get("name") or app.get("id") or ""
        app_cache[app_id] = name or app_id
        return app_cache[app_id]

    def _replace_client_ids(conditions):
        if not isinstance(conditions, dict):
            return conditions
        clients = conditions.get("clients")
        if not isinstance(clients, dict):
            return conditions
        updated = dict(conditions)
        updated_clients = dict(clients)
        for key in ("include", "exclude"):
            ids = updated_clients.get(key)
            if isinstance(ids, list):
                updated_clients[key] = [
                    _resolve_app_name(app_id) if app_id != "ALL_CLIENTS" else "ALL_CLIENTS"
                    for app_id in ids
                ]
        updated["clients"] = updated_clients
        return updated

    def _format_duration(minutes):
        if minutes is None:
            return "Not set"
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return str(minutes)
        if minutes % 1440 == 0:
            return f"{minutes // 1440} Days"
        if minutes % 60 == 0:
            return f"{minutes // 60} Hours"
        return f"{minutes} Minutes"

    def _format_grant_type(grant_type):
        mapping = {
            "authorization_code": "Authorization Code",
            "client_credentials": "Client Credentials",
            "password": "Resource Owner Password",
            "implicit": "Implicit",
            "refresh_token": "Refresh Token",
            "interaction_code": "Interaction Code",
            "urn:openid:params:grant-type:ciba": "CIBA",
            "urn:ietf:params:oauth:grant-type:device_code": "Device Authorization",
            "urn:ietf:params:oauth:grant-type:token-exchange": "Token Exchange",
            "urn:ietf:params:oauth:grant-type:saml2-bearer": "SAML 2.0 Bearer",
            "urn:ietf:params:oauth:grant-type:jwt-bearer": "JWT Bearer",
            "http://auth0.com/oauth/grant-type/mfa-otp": "MFA OTP",
            "urn:okta:params:oauth:grant-type:oob": "OOB",
        }
        return mapping.get(grant_type, grant_type)

    def _format_conditions(conditions):
        if not isinstance(conditions, dict):
            return conditions
        parts = []
        grant_types = (conditions.get("grantTypes") or {}).get("include") or []
        if grant_types:
            labels = [_format_grant_type(gt) for gt in grant_types]
            parts.append(f"Grant types: {', '.join(labels)}")
        clients = (conditions.get("clients") or {}).get("include")
        if clients:
            if clients == ["ALL_CLIENTS"]:
                parts.append("Client: Any client")
            else:
                parts.append(f"Client: {', '.join(clients)}")
        people = conditions.get("people") or {}
        groups = (people.get("groups") or {}).get("include") or []
        users = (people.get("users") or {}).get("include") or []
        if groups or users:
            group_label = ", ".join(groups) if groups else "None"
            user_label = ", ".join(users) if users else "None"
            parts.append(f"User is: Groups [{group_label}] Users [{user_label}]")
        scopes = (conditions.get("scopes") or {}).get("include") or []
        if scopes:
            scope_label = "Any scopes" if scopes == ["*"] else ", ".join(scopes)
            parts.append(f"Scopes requested: {scope_label}")
        return "; ".join(parts) if parts else "Any"

    def _format_actions(actions):
        if not isinstance(actions, dict):
            return actions
        token = actions.get("token") or {}
        inline_hook = actions.get("inlineHook") or {}
        parts = []
        access_life = token.get("accessTokenLifetimeMinutes")
        refresh_life = token.get("refreshTokenLifetimeMinutes")
        refresh_window = token.get("refreshTokenWindowMinutes")
        if access_life is not None:
            parts.append(f"Access token lifetime: {_format_duration(access_life)}")
        if refresh_life is not None:
            parts.append(f"Refresh token lifetime: {_format_duration(refresh_life)}")
        if refresh_window is not None:
            parts.append(f"Refresh token window: {_format_duration(refresh_window)}")
        hook_id = inline_hook.get("id")
        if hook_id:
            parts.append(f"Inline hook: {hook_id}")
        return "; ".join(parts) if parts else "None"

    for server in servers:
        server_id = server.get("id")
        server_name = server.get("name")
        policies = get_authorization_server_policies(domain_url, api_token, server_id) or []
        for policy in policies:
            policy_id = policy.get("id")
            policy_name = policy.get("name")
            policy_rows.append({
                "Authorization Server": server_name,
                "Policy ID": policy_id,
                "Policy Name": policy_name,
                "Status": policy.get("status"),
                "Description": policy.get("description"),
                "Priority": policy.get("priority"),
                "Conditions": _format_conditions(_replace_client_ids(policy.get("conditions"))),
            })

            rules = get_authorization_server_policy_rules(domain_url, api_token, server_id, policy_id) or []
            for rule in rules:
                rule_rows.append({
                    "Authorization Server": server_name,
                    "Policy Name": policy_name,
                    "Rule ID": rule.get("id"),
                    "Rule Name": rule.get("name"),
                    "Status": rule.get("status"),
                    "Priority": rule.get("priority"),
                    "Conditions": _format_conditions(_replace_client_ids(rule.get("conditions"))),
                    "Actions": _format_actions(rule.get("actions")),
                })

    return policy_rows, rule_rows
