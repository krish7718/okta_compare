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


def _next_link(headers):
    link = headers.get("Link")
    if link:
        for part in link.split(","):
            if 'rel="next"' in part:
                return part.split(";")[0].strip().strip("<>")
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
        logger.info("Fetched %s IdP app user type(s).", len(data))
        return data
    logger.info("No IdP app user types returned.")
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
    page = 0
    seen_urls = set()
    while url:
        if url in seen_urls:
            logger.warning("Detected repeated profile mappings pagination URL, stopping loop at %s.", url)
            break
        seen_urls.add(url)
        page += 1
        logger.info("Requesting profile mappings page %s.", page)
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
            logger.info(
                "Fetched %s profile mapping(s) from page %s; accumulated total=%s.",
                len(data),
                page,
                len(mappings),
            )
        else:
            logger.error("Unexpected response format for profile mappings: %s", type(data))
            break

        next_link = _next_link(resp.headers)
        if next_link:
            url = next_link
            logger.info("Profile mappings pagination continues after page %s.", page)
        else:
            url = None
            logger.info("Profile mappings pagination complete after %s page(s).", page)

    logger.info("Returning %s total profile mapping(s).", len(mappings))
    return mappings


def get_profile_mapping_by_id(domain_url, api_token, mapping_id):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/mappings/{mapping_id}"
    logger.info("Fetching profile mapping detail for mapping_id=%s.", mapping_id)
    data = _get_json(url, headers, "Error fetching profile mapping detail")
    if isinstance(data, dict):
        logger.info("Fetched profile mapping detail for mapping_id=%s.", mapping_id)
        return data
    logger.warning("Profile mapping detail unavailable for mapping_id=%s.", mapping_id)
    return None
