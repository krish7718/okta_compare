import requests
from urllib.parse import urlparse

def _ensure_domain_str(domain_url):
    """
    Normalize and validate domain_url. Returns scheme://netloc string.
    Raises TypeError/ValueError for invalid inputs.
    """
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")

    # Reject obvious JSON/list representations
    if domain_url.strip().startswith(("[", "{")):
        raise ValueError(f"Invalid domain_url value (looks like JSON/list): {domain_url!r}")

    candidate = domain_url if domain_url.startswith(('http://', 'https://')) else f"https://{domain_url}"
    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid domain_url (could not parse host): {domain_url!r}")
    if any(ch in parsed.netloc for ch in "{}[]"):
        raise ValueError(f"Invalid domain_url (contains invalid characters): {domain_url!r}")

    return f"{parsed.scheme}://{parsed.netloc}"


def get_applications(domain_url, api_token):
    """
    Fetch all Okta applications from the given domain using the provided API token.
    Handles pagination via the Link header. Returns a list of application dicts.
    """
    headers = {
        'Authorization': f"SSWS {api_token}",
        'Accept': 'application/json'
    }

    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip('/')
    url = base + '/api/v1/apps'

    apps = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"Error fetching applications: {resp.status_code} {resp.text}")
            break

        try:
            data = resp.json()
        except ValueError:
            print("Invalid JSON received for applications")
            break

        if isinstance(data, list):
            apps.extend(data)
        else:
            # unexpected shape, attempt to handle common wrapper
            if isinstance(data, dict) and 'applications' in data and isinstance(data['applications'], list):
                apps.extend(data['applications'])
            else:
                print("Unexpected response format for applications:", type(data))
                break

        next_link = resp.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
        else:
            url = None

    return apps


def get_application_groups(domain_url, api_token, app_id):
    """
    Fetch groups assigned to a specific application.
    Endpoint: /api/v1/apps/{appId}/groups
    Returns a list of group objects (may be empty).
    """
    if not app_id:
        return []

    headers = {
        'Authorization': f"SSWS {api_token}",
        'Accept': 'application/json'
    }

    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip('/')
    url = f"{base}/api/v1/apps/{app_id}/groups"

    groups = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"Error fetching groups for app {app_id}: {resp.status_code} {resp.text}")
            break

        try:
            data = resp.json()
        except ValueError:
            print(f"Invalid JSON received for application groups (app {app_id})")
            break

        if isinstance(data, list):
            groups.extend(data)
        else:
            print("Unexpected response format for application groups:", type(data))
            break

        next_link = resp.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
        else:
            url = None

    return groups