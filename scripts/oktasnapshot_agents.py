import json
import logging

from scripts.extract_agents import get_agent_pools_with_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_agents_view(domain_url, api_token):
    logger.info("Fetching agents for OktaView.")
    pools = get_agent_pools_with_settings(domain_url, api_token) or []
    rows = []
    for pool in pools:
        update_settings = pool.get("updateSettings") or {}
        rows.append({
            "Agent Pool ID": pool.get("id"),
            "Name": pool.get("name"),
            "Pool Type": pool.get("poolType"),
            "Type": pool.get("type"),
            "Status": pool.get("status"),
            "Operational Status": pool.get("operationalStatus"),
            "Created": pool.get("created"),
            "Last Updated": pool.get("lastUpdated"),
            "Update Settings": json.dumps(update_settings, sort_keys=True, default=str),
        })
    return rows
