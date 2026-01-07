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


def get_authenticators(domain_url, api_token, limit=200):
    """
    Fetch all Okta authenticators for the given domain using the provided API token.
    Handles pagination via the Link header. Returns a list of authenticator dicts.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authenticators.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authenticators?limit={limit}"

    authenticators = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching authenticators: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for authenticators")
            break

        if isinstance(data, list):
            authenticators.extend(data)
        else:
            logger.error("Unexpected response format for authenticators: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return authenticators
