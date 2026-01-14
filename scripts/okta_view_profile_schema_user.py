import logging
import json

from scripts.extract_profile_schema import get_user_type_id, get_user_profile_schemas

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_profile_schema_user_view(domain_url, api_token):
    logger.info("Fetching user profile schema for OktaView.")
    user_type_id = get_user_type_id(domain_url, api_token)
    if not user_type_id:
        return []
    schemas = get_user_profile_schemas(domain_url, api_token, user_type_id) or []
    rows = []
    for schema in schemas:
        properties = (schema.get("schema") or {}).get("properties") or {}
        for name, settings in properties.items():
            rows.append({
                "Attribute": name,
                "Title": settings.get("title"),
                "Type": settings.get("type"),
                "Required": settings.get("required"),
                "Mutability": settings.get("mutability"),
                "Scope": settings.get("scope"),
                "Validation Type": settings.get("validationType"),
                "Settings": json.dumps(settings, sort_keys=True, default=str),
            })
    return rows
