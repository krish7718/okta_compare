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
        return None
    try:
        return resp.json()
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None


def get_idp_app_user_types(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching IdP app user types.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/user/types?expand=app,appLogo&category=idp"

    data = _get_json(url, headers, "Error fetching IdP app user types")
    if isinstance(data, list):
        return data
    return []


def get_user_type_id(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/user/types"
    data = _get_json(url, headers, "Error fetching user types")
    if not isinstance(data, list):
        return None
    for item in data:
        if item.get("name") == "user" or item.get("displayName") == "User":
            return item.get("id")
    return None


def get_profile_mappings(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching profile mappings.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/mappings?limit={limit}"

    mappings = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching profile mappings: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for profile mappings")
            break

        if isinstance(data, list):
            mappings.extend(data)
        else:
            logger.error("Unexpected response format for profile mappings: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return mappings


def get_profile_mapping_by_id(domain_url, api_token, mapping_id):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/mappings/{mapping_id}"
    data = _get_json(url, headers, "Error fetching profile mapping detail")
    if isinstance(data, dict):
        return data
    return None
