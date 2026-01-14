import logging

from scripts.extract_authorization_servers import (
    get_authorization_servers,
    get_authorization_server_claims,
    get_authorization_server_scopes,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_authorization_server_settings_view(domain_url, api_token):
    logger.info("Fetching authorization server settings for OktaView.")
    servers = get_authorization_servers(domain_url, api_token) or []
    server_rows = []
    claim_rows = []
    scope_rows = []

    for server in servers:
        server_id = server.get("id")
        server_name = server.get("name")
        server_rows.append({
            "ID": server_id,
            "Name": server_name,
            "Status": server.get("status"),
            "Description": server.get("description"),
            "Audiences": ", ".join(server.get("audiences") or []),
            "Issuer": server.get("issuer"),
            "Credentials Rotation Mode": (server.get("credentials", {}) or {}).get("signing", {}).get("rotationMode"),
        })

        claims = get_authorization_server_claims(domain_url, api_token, server_id) or []
        for claim in claims:
            claim_rows.append({
                "Authorization Server": server_name,
                "Claim Name": claim.get("name"),
                "Status": claim.get("status"),
                "Claim Type": claim.get("claimType"),
                "Value Type": claim.get("valueType"),
                "Value": claim.get("value"),
                "Include In Token Type": claim.get("conditions", {}).get("scopes"),
            })

        scopes = get_authorization_server_scopes(domain_url, api_token, server_id) or []
        for scope in scopes:
            scope_rows.append({
                "Authorization Server": server_name,
                "Scope Name": scope.get("name"),
                "Display Name": scope.get("displayName"),
                "Description": scope.get("description"),
                "System": scope.get("system"),
                "Consent": scope.get("consent"),
            })

    return server_rows, claim_rows, scope_rows
