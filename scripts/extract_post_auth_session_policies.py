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
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def get_post_auth_session_policies(domain_url, api_token, limit=200):
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    logger.info("Fetching post-auth session policies.")
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/policies?type=POST_AUTH_SESSION&limit={limit}"

    policies = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching post-auth session policies: %s %s", resp.status_code, resp.text)
            break
        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for post-auth session policies")
            break
        if isinstance(data, list):
            policies.extend(data)
        else:
            logger.error("Unexpected response format for post-auth session policies: %s", type(data))
            break
        next_link = resp.headers.get("Link")
        if next_link and 'rel=\"next\"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None
    return policies


def get_post_auth_session_policy_rules(domain_url, api_token, policy_id):
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}
    logger.info("Fetching post-auth session policy rules for policy_id=%s.", policy_id)
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/policies/{policy_id}/rules"

    rules = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error(
                "Error fetching post-auth session policy rules for %s: %s %s",
                policy_id,
                resp.status_code,
                resp.text,
            )
            break
        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for post-auth session policy rules (policy %s)", policy_id)
            break
        if isinstance(data, list):
            rules.extend(data)
        else:
            logger.error("Unexpected response format for post-auth session policy rules: %s", type(data))
            break
        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None
    return rules
