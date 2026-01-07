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


def get_password_policies(domain_url, api_token, limit=200):
    """
    Fetch all password policies (type = PASSWORD).
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching password policies.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/policies?type=PASSWORD&limit={limit}"

    policies = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching password policies: %s %s", resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for password policies")
            break

        if isinstance(data, list):
            policies.extend(data)
        else:
            logger.error("Unexpected response format for password policies: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return policies


def get_password_policy_rules(domain_url, api_token, policy_id):
    """
    Fetch rules for a given password policy.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching password policy rules for policy_id=%s.", policy_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/policies/{policy_id}/rules"

    rules = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error(
                "Error fetching password policy rules for %s: %s %s",
                policy_id,
                resp.status_code,
                resp.text,
            )
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for password policy rules (policy %s)", policy_id)
            break

        if isinstance(data, list):
            rules.extend(data)
        else:
            logger.error("Unexpected response format for password policy rules: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return rules
