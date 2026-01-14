import logging
import json

from scripts.extract_trusted_origins import get_trusted_origins

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_trusted_origins_view(domain_url, api_token):
    logger.info("Fetching trusted origins for OktaView.")
    origins = get_trusted_origins(domain_url, api_token) or []
    rows = []
    for origin in origins:
        rows.append({
            "Origin ID": origin.get("id"),
            "Name": origin.get("name"),
            "Origin": origin.get("origin"),
            "Status": origin.get("status"),
            "Scopes": json.dumps(origin.get("scopes") or [], sort_keys=True, default=str),
            "Created": origin.get("created"),
            "Last Updated": origin.get("lastUpdated"),
        })
    return rows
