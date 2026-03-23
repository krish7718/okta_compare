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


def _headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }


def get_agent_pools(domain_url, api_token, limit_per_pool_type=200, pool_type=None, after=None):
    logger.info("Fetching agent pools.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/agentPools"
    headers = _headers(api_token)

    pools = []
    next_after = after

    while True:
        params = {"limitPerPoolType": limit_per_pool_type}
        if pool_type:
            params["poolType"] = pool_type
        if next_after:
            params["after"] = next_after

        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code != 200:
            logger.error("Error fetching agent pools: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for agent pools")
            break

        if not isinstance(data, list):
            logger.error("Unexpected response format for agent pools: %s", type(data))
            break

        pools.extend(data)

        link_header = resp.headers.get("Link", "")
        next_url = None
        for part in link_header.split(","):
            if 'rel="next"' in part:
                next_url = part.split(";")[0].strip().strip("<>")
                break

        if next_url:
            next_after = None
            url = next_url
            continue

        break

    return pools


def get_agent_pool_update_settings(domain_url, api_token, pool_id):
    logger.info("Fetching agent pool update settings for pool_id=%s.", pool_id)
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/agentPools/{pool_id}/updates/settings"

    resp = requests.get(url, headers=_headers(api_token))
    if resp.status_code != 200:
        logger.error(
            "Error fetching agent pool update settings for %s: %s %s",
            pool_id,
            resp.status_code,
            resp.text,
        )
        return {}

    try:
        data = resp.json()
    except ValueError:
        logger.error("Invalid JSON received for agent pool update settings: %s", pool_id)
        return {}

    if not isinstance(data, dict):
        logger.error("Unexpected update settings format for agent pool %s: %s", pool_id, type(data))
        return {}

    return data


def get_agent_pools_with_settings(domain_url, api_token, limit_per_pool_type=200, pool_type=None):
    pools = get_agent_pools(
        domain_url,
        api_token,
        limit_per_pool_type=limit_per_pool_type,
        pool_type=pool_type,
    ) or []

    enriched = []
    for pool in pools:
        pool_copy = dict(pool)
        pool_id = pool_copy.get("id")
        if pool_id:
            pool_copy["updateSettings"] = get_agent_pool_update_settings(domain_url, api_token, pool_id)
        else:
            pool_copy["updateSettings"] = {}
        enriched.append(pool_copy)

    return enriched
