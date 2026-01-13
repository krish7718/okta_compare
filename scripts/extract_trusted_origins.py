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


def get_trusted_origins(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching trusted origins.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/trustedOrigins?limit={limit}"

    origins = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching trusted origins: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for trusted origins")
            break

        if isinstance(data, list):
            origins.extend(data)
        else:
            logger.error("Unexpected response format for trusted origins: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return origins
