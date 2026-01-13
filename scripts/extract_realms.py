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


def _get_json(url, headers, error_label):
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
        return None, resp
    try:
        return resp.json(), resp
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None, resp


def get_realms(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching realms.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/realms?limit={limit}"

    realms = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching realms")
        if data is None:
            break

        if isinstance(data, list):
            realms.extend(data)
        else:
            logger.error("Unexpected response format for realms: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return realms


def get_realm_assignments(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching realm assignments.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/realm-assignments?limit={limit}"

    assignments = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching realm assignments")
        if data is None:
            break

        if isinstance(data, list):
            assignments.extend(data)
        else:
            logger.error("Unexpected response format for realm assignments: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return assignments
