import logging
from urllib.parse import quote

from scripts.oktasnapshot_utils import ensure_domain_str, get_paginated

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }


def get_users(domain_url, api_token, limit=200, search=None):
    base = ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/users?limit={limit}"
    if search:
        url = f"{url}&search={quote(search, safe='()\" ')}"
    logger.info("Fetching users from %s.", url)
    users = get_paginated(url, _headers(api_token), "Error fetching users") or []
    if search:
        logger.info("Fetched %s user(s) for search=%s.", len(users), search)
    else:
        logger.info("Fetched %s active/non-filtered user(s).", len(users))
    return users


def get_all_users(domain_url, api_token, limit=200, include_deprovisioned=True):
    users = {}
    primary_users = get_users(domain_url, api_token, limit=limit) or []
    logger.info("Processing %s primary user record(s).", len(primary_users))
    for user in primary_users:
        user_id = user.get("id")
        if user_id:
            users[user_id] = user

    if include_deprovisioned:
        deprov_users = get_users(
            domain_url,
            api_token,
            limit=limit,
            search='status eq "DEPROVISIONED"',
        ) or []
        logger.info("Processing %s deprovisioned user record(s).", len(deprov_users))
        for user in deprov_users:
            user_id = user.get("id")
            if user_id:
                users[user_id] = user

    all_users = list(users.values())
    logger.info("Returning %s total unique user record(s).", len(all_users))
    return all_users


def get_user_factors(domain_url, api_token, user_id):
    if not user_id:
        return []
    base = ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/users/{user_id}/factors"
    logger.info("Fetching factors for user_id=%s.", user_id)
    factors = get_paginated(url, _headers(api_token), f"Error fetching factors for user {user_id}") or []
    logger.info("Fetched %s factor(s) for user_id=%s.", len(factors), user_id)
    return factors


def get_user_roles(domain_url, api_token, user_id):
    if not user_id:
        return []
    base = ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/users/{user_id}/roles"
    logger.info("Fetching roles for user_id=%s.", user_id)
    roles = get_paginated(url, _headers(api_token), f"Error fetching roles for user {user_id}") or []
    logger.info("Fetched %s role assignment(s) for user_id=%s.", len(roles), user_id)
    return roles


def get_users_with_security_context(domain_url, api_token, limit=200):
    users = get_all_users(domain_url, api_token, limit=limit, include_deprovisioned=True) or []
    logger.info("Enriching %s user(s) with factors and role context.", len(users))
    enriched = []
    for idx, user in enumerate(users, start=1):
        user_id = user.get("id")
        status = str(user.get("status") or "").upper()
        factors = []
        roles = []
        if idx == 1 or idx % 25 == 0:
            logger.info("User enrichment progress: processing user %s/%s (user_id=%s, status=%s).", idx, len(users), user_id, status)
        if user_id and status != "DEPROVISIONED":
            factors = get_user_factors(domain_url, api_token, user_id) or []
            roles = get_user_roles(domain_url, api_token, user_id) or []
        combined = dict(user)
        combined["factors"] = factors
        combined["roles"] = roles
        enriched.append(combined)
    logger.info("Completed user security-context enrichment for %s user(s).", len(enriched))
    return enriched
