import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _ensure_domain_str(domain_url):
    """Ensure domain_url is a valid HTTPS string."""
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"



def get_api_tokens(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching API tokens.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/api-tokens?limit={limit}"

    tokens = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching API tokens: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for API tokens")
            break

        if isinstance(data, list):
            tokens.extend(data)
        else:
            logger.error("Unexpected response format for API tokens: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return tokens


def get_api_token_metadata(domain_url, api_token, api_token_id):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    if not api_token_id:
        return None

    logger.info("Fetching API token metadata for api_token_id=%s.", api_token_id)
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/api-tokens/{api_token_id}"

    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("Error fetching API token metadata for %s: %s %s", api_token_id, resp.status_code, resp.text)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("Invalid JSON received for API token metadata (%s)", api_token_id)
        return None

    return data if isinstance(data, dict) else None


def get_api_tokens_with_metadata(domain_url, api_token, limit=200):
    tokens = get_api_tokens(domain_url, api_token, limit=limit) or []
    enriched = []
    for token in tokens:
        token_id = token.get("id")
        metadata = get_api_token_metadata(domain_url, api_token, token_id) or {}
        combined = dict(token)
        combined.update(metadata)
        enriched.append(combined)
    return enriched
