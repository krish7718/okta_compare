import logging

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


def _extract_values(items):
    if not items:
        return ""
    values = []
    for item in items:
        if isinstance(item, dict):
            if item.get("value"):
                values.append(item.get("value"))
    return ", ".join(values)


def get_network_zones(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching network zones for OktaView.")
    url = f"{base}/api/v1/zones"
    zones = get_paginated(url, _headers(api_token), "Error fetching network zones") or []
    logger.info("Fetched %s network zone record(s) for OktaView.", len(zones))
    results = []
    for idx, zone in enumerate(zones, start=1):
        if idx == 1 or idx % 10 == 0:
            logger.info("Network zone rendering progress: processing zone %s/%s.", idx, len(zones))
        results.append({
            "Name": zone.get("name"),
            "Status": zone.get("status"),
            "Gateways": _extract_values(zone.get("gateways", [])),
            "Proxies": _extract_values(zone.get("proxies", [])),
            "Usage": zone.get("usage"),
        })
    logger.info("Completed OktaView network zone rendering with %s row(s).", len(results))
    return results
