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
    page = 0
    while url:
        page += 1
        logger.info("Requesting groups page %s for group-rule name resolution.", page)
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error("Error fetching groups: %s", response.status_code)
            break

        data = response.json()
        logger.info("Fetched %s group record(s) on page %s.", len(data) if isinstance(data, list) else 0, page)
        for group in data:
            groups_map[group['id']] = group['profile']['name']
        logger.info("Accumulated %s group name mapping(s) so far.", len(groups_map))

        next_link = response.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
            logger.info("Groups pagination continues after page %s.", page)
        else:
            url = None
            logger.info("Groups pagination complete after %s page(s).", page)

    logger.info("Completed groups map build with %s total entries.", len(groups_map))
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
    page = 0
    while url:
        page += 1
        logger.info("Requesting group rules page %s.", page)
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error("Error fetching group rules: %s", response.status_code)
            break

        data = response.json()
        rules.extend(data)
        logger.info(
            "Fetched %s group rule(s) from page %s; accumulated total=%s.",
            len(data) if isinstance(data, list) else 0,
            page,
            len(rules),
        )

        next_link = response.headers.get('Link')
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(';')[0].strip('<>')
            logger.info("Group rules pagination continues after page %s.", page)
        else:
            url = None
            logger.info("Group rules pagination complete after %s page(s).", page)

    logger.info("Returning %s total group rule(s).", len(rules))
    return rules
