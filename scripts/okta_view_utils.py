import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def ensure_domain_str(domain_url):
    """Ensure domain_url is a valid HTTPS string."""
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def get_json(url, headers, error_label):
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
        return None
    try:
        return resp.json()
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None


def _next_link(headers):
    link = headers.get("Link")
    if link and 'rel="next"' in link:
        return link.split(";")[0].strip("<>")
    return None


def get_paginated(url, headers, error_label):
    items = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
            break
        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for %s", error_label)
            break
        if not isinstance(data, list):
            logger.error("Unexpected response format for %s: %s", error_label, type(data))
            break
        items.extend(data)
        url = _next_link(resp.headers)
    return items
