import logging
import requests
from urllib.parse import urlparse

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


def _admin_domain(domain_url):
    parsed = urlparse(_ensure_domain_str(domain_url))
    host = parsed.netloc
    if host.endswith("-admin.oktapreview.com") or host.endswith("-admin.okta.com"):
        return f"{parsed.scheme}://{host}"
    if host.endswith(".oktapreview.com"):
        sub = host.split(".")[0]
        return f"{parsed.scheme}://{sub}-admin.oktapreview.com"
    if host.endswith(".okta.com"):
        sub = host.split(".")[0]
        return f"{parsed.scheme}://{sub}-admin.okta.com"
    return f"{parsed.scheme}://{host}"


def _extract_list(data, key):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and key in data and isinstance(data[key], list):
        return data[key]
    return None


def get_custom_admin_roles(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching custom admin roles.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/iam/roles?limit={limit}"

    roles = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching custom admin roles")
        if data is None:
            break

        items = _extract_list(data, "roles")
        if items is None:
            logger.error("Unexpected response format for custom admin roles: %s", type(data))
            break

        roles.extend(items)

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return roles


def get_resource_sets(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching resource sets.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/iam/resource-sets?limit={limit}"

    sets = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching resource sets")
        if data is None:
            break

        items = _extract_list(data, "resource-sets")
        if items is None:
            logger.error("Unexpected response format for resource sets: %s", type(data))
            break

        sets.extend(items)

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return sets


def get_resource_set_resources(domain_url, api_token, resource_set_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching resource set resources for resource_set_id=%s.", resource_set_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/iam/resource-sets/{resource_set_id}/resources?limit={limit}"

    resources = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching resources for resource set {resource_set_id}")
        if data is None:
            break

        if isinstance(data, list):
            resources.extend(data)
        else:
            logger.error("Unexpected response format for resource set resources: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return resources


def get_resource_set_bindings(domain_url, api_token, resource_set_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching resource set bindings for resource_set_id=%s.", resource_set_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/iam/resource-sets/{resource_set_id}/bindings?limit={limit}"

    bindings = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching bindings for resource set {resource_set_id}")
        if data is None:
            break

        if isinstance(data, list):
            bindings.extend(data)
        else:
            logger.error("Unexpected response format for resource set bindings: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return bindings


def get_binding_members(domain_url, api_token, resource_set_id, binding_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching binding members for binding_id=%s.", binding_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/iam/resource-sets/{resource_set_id}/bindings/{binding_id}/members?limit={limit}"

    members = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching members for binding {binding_id}")
        if data is None:
            break

        if isinstance(data, list):
            members.extend(data)
        else:
            logger.error("Unexpected response format for binding members: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return members


def get_admin_users(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    admin_base = _admin_domain(domain_url)
    url = f"{admin_base}/api/internal/privileges/admins"
    logger.info("Fetching admin assignments from %s.", url)
    data, _ = _get_json(url, headers, "Error fetching admin assignments")
    if isinstance(data, list):
        return data
    logger.error("Unexpected response format for admin assignments: %s", type(data))
    return []


def get_admin_groups(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    admin_base = _admin_domain(domain_url)
    url = f"{admin_base}/api/internal/privileges/adminGroups"
    logger.info("Fetching admin groups from %s.", url)
    data, _ = _get_json(url, headers, "Error fetching admin groups")
    if isinstance(data, list):
        return data
    logger.error("Unexpected response format for admin groups: %s", type(data))
    return []


def get_admin_apps(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    admin_base = _admin_domain(domain_url)
    url = f"{admin_base}/admin/api/v1/privileges/adminPublicClientApps"
    logger.info("Fetching admin apps from %s.", url)
    data, _ = _get_json(url, headers, "Error fetching admin apps")
    if isinstance(data, list):
        return data
    logger.error("Unexpected response format for admin apps: %s", type(data))
    return []
