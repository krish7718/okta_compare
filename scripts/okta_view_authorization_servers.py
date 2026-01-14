import logging

from scripts.okta_view_utils import ensure_domain_str, get_paginated

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }


def get_authorization_servers(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching authorization servers for OktaView.")
    url = f"{base}/api/v1/authorizationServers"
    servers = get_paginated(url, _headers(api_token), "Error fetching authorization servers") or []
    results = []
    for server in servers:
        results.append({
            "ID": server.get("id"),
            "Name": server.get("name"),
            "Status": server.get("status"),
            "Description": server.get("description"),
            "Audiences": ", ".join(server.get("audiences") or []),
            "Issuer": server.get("issuer"),
            "Credentials Rotation Mode": (server.get("credentials", {}) or {}).get("signing", {}).get("rotationMode"),
        })
    return results
