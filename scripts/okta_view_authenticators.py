import logging

from scripts.extract_authenticators import get_authenticators

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_authenticators_view(domain_url, api_token):
    logger.info("Fetching authenticators for OktaView.")
    authenticators = get_authenticators(domain_url, api_token) or []
    rows = []
    for auth in authenticators:
        rows.append({
            "Name": auth.get("name") or auth.get("label"),
            "Key": auth.get("key"),
            "Type": auth.get("type"),
            "Status": auth.get("status"),
        })
    return rows
