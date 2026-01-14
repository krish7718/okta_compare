import logging
import json

from scripts.extract_profile_mappings import (
    get_profile_mappings,
    get_profile_mapping_by_id,
    get_idp_app_user_types,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_profile_mappings_view(domain_url, api_token):
    logger.info("Fetching profile mappings for OktaView.")
    idp_types = get_idp_app_user_types(domain_url, api_token) or []
    idp_names = {t.get("name") for t in idp_types if t.get("name")}

    mappings = get_profile_mappings(domain_url, api_token) or []
    rows = []

    for mapping in mappings:
        source = mapping.get("source") or {}
        target = mapping.get("target") or {}
        if source.get("name") not in idp_names and target.get("name") not in idp_names:
            continue
        detail = get_profile_mapping_by_id(domain_url, api_token, mapping.get("id")) or {}
        rows.append({
            "Mapping ID": mapping.get("id"),
            "Source Name": source.get("name"),
            "Target Name": target.get("name"),
            "Properties": json.dumps(detail.get("properties") or detail.get("propertyMappings"), sort_keys=True, default=str),
        })

    return rows
