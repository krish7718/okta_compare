import logging

from scripts.extract_api_tokens import get_api_tokens

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_api_tokens_view(domain_url, api_token):
    logger.info("Fetching API tokens for OktaView.")
    tokens = get_api_tokens(domain_url, api_token) or []
    rows = []
    for token in tokens:
        rows.append({
            "Token ID": token.get("id"),
            "Name": token.get("name"),
            "User ID": token.get("userId"),
            "Client Name": token.get("clientName"),
            "Token Window": token.get("tokenWindow"),
            "Network": token.get("network"),
            "Created": token.get("created"),
            "Last Updated": token.get("lastUpdated"),
            "Expires At": token.get("expiresAt"),
        })
    return rows
