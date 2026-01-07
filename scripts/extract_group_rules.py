import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")

def _ensure_domain_str(domain_url):
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(('http://', 'https://')) else f"https://{domain_url}"

def get_groups_map(domain_url, api_token):
    headers = {
        'Authorization': f"SSWS {api_token}",
        'Accept': 'application/json'
    }

    logger.info("Fetching groups map for group rules.")
    groups_map = {}
    # validate domain_url to avoid passing lists/dicts into requests
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip('/')
    url = base + '/api/v1/groups'
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error("Error fetching groups: %s", response.status_code)
            break

        for group in response.json():
            groups_map[group['id']] = group['profile']['name']

        next_link = response.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
        else:
            url = None

    return groups_map


def get_group_rules(domain_url, api_token):
    headers = {
        'Authorization': f"SSWS {api_token}",
        'Accept': 'application/json'
    }

    logger.info("Fetching group rules.")
    rules = []
    # validate domain_url to avoid passing lists/dicts into requests
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip('/')
    url = base + '/api/v1/groups/rules'
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error("Error fetching group rules: %s", response.status_code)
            break

        rules.extend(response.json())

        next_link = response.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
        else:
            url = None

    return rules
