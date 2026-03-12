import json
import logging

from scripts.extract_group_push_mappings import get_group_push_mappings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_group_push_mappings_view(domain_url, api_token):
    logger.info("Fetching group push mappings for OktaView.")
    mappings = get_group_push_mappings(domain_url, api_token) or []
    rows = []
    for mapping in mappings:
        app = mapping.get("_app") or {}
        rows.append({
            "App Name": app.get("label") or app.get("name"),
            "App Type": app.get("name") or app.get("signOnMode"),
            "Mapping ID": mapping.get("id"),
            "Status": mapping.get("status"),
            "Source Group": mapping.get("sourceGroupName") or mapping.get("sourceGroup") or mapping.get("sourceGroupId"),
            "Target Group": mapping.get("targetGroupName") or mapping.get("targetGroup") or mapping.get("targetGroupId"),
            "Last Updated": mapping.get("lastUpdated"),
            "Settings": json.dumps(mapping, sort_keys=True, default=str),
        })
    return rows
