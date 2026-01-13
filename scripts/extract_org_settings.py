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


def get_org_settings(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching org general settings.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/org"

    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("Error fetching org general settings: %s %s", resp.status_code, resp.text)
        return None

    try:
        return resp.json()
    except ValueError:
        logger.error("Invalid JSON received for org general settings")
        return None
