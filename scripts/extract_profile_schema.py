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


def _admin_domain(domain_url):
    base = _ensure_domain_str(domain_url)
    if "://" not in base:
        base = f"https://{base}"
    scheme, rest = base.split("://", 1)
    host = rest.split("/", 1)[0]
    if host.endswith("-admin.oktapreview.com") or host.endswith("-admin.okta.com"):
        return f"{scheme}://{host}"
    if host.endswith(".oktapreview.com"):
        sub = host.split(".")[0]
        return f"{scheme}://{sub}-admin.oktapreview.com"
    if host.endswith(".okta.com"):
        sub = host.split(".")[0]
        return f"{scheme}://{sub}-admin.okta.com"
    return f"{scheme}://{host}"


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


def get_user_type_id(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    admin_base = _admin_domain(domain_url).rstrip("/")
    url = f"{admin_base}/api/v1/user/types"
    logger.info("Fetching user types.")
    data = _get_json(url, headers, "Error fetching user types")
    if not isinstance(data, list):
        return None
    for item in data:
        if item.get("name") == "user" or item.get("displayName") == "User":
            return item.get("id")
    return None


def get_user_profile_schemas(domain_url, api_token, user_type_id):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    admin_base = _admin_domain(domain_url).rstrip("/")
    url = f"{admin_base}/api/v1/user/types/{user_type_id}/schemas"
    logger.info("Fetching user profile schemas for user_type_id=%s.", user_type_id)
    data = _get_json(url, headers, "Error fetching user profile schemas")
    if not isinstance(data, list):
        return []
    return data
