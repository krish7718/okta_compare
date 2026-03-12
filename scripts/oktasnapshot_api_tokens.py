import logging

from scripts.extract_api_tokens import get_api_tokens_with_metadata
from scripts.oktasnapshot_utils import ensure_domain_str, get_paginated

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


def _zone_name_map(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    zones = get_paginated(f"{base}/api/v1/zones", _headers(api_token), "Error fetching network zones") or []
    return {zone.get("id"): zone.get("name") for zone in zones if zone.get("id")}


def _network_label(network, zone_map):
    if not isinstance(network, dict):
        return network
    connection = network.get("connection")
    include = network.get("include") or []
    exclude = network.get("exclude") or []
    include_names = [zone_map.get(zone_id, zone_id) for zone_id in include]
    exclude_names = [zone_map.get(zone_id, zone_id) for zone_id in exclude]
    return {
        "connection": connection,
        "include": include_names,
        "exclude": exclude_names,
    }


def get_api_tokens_view(domain_url, api_token):
    logger.info("Fetching API tokens for OktaView.")
    tokens = get_api_tokens_with_metadata(domain_url, api_token) or []
    zone_map = _zone_name_map(domain_url, api_token)
    rows = []
    for token in tokens:
        rows.append({
            "Token ID": token.get("id"),
            "Name": token.get("name"),
            "User ID": token.get("userId"),
            "Client Name": token.get("clientName"),
            "Status": token.get("status"),
            "Network": _network_label(token.get("network"), zone_map),
            "Created": token.get("created"),
            "Last Updated": token.get("lastUpdated"),
            "Expires At": token.get("expiresAt"),
            "Last Updated By": token.get("lastUpdatedBy"),
        })
    return rows
