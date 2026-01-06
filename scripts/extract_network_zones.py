import requests

def _ensure_domain_str(domain_url):
    """Ensure domain URL is a proper https:// URL."""
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def get_network_zones(domain_url, api_token):
    """Fetch all network zones."""
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json"
    }

    zones = []
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = base + "/api/v1/zones"

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print("Error fetching network zones:", response.status_code)
            break

        zones.extend(response.json())

        next_link = response.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return zones
