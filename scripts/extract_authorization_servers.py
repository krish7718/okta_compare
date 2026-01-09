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


def get_authorization_servers(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authorization servers.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authorizationServers?limit={limit}"

    servers = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching authorization servers")
        if data is None:
            break

        if isinstance(data, list):
            servers.extend(data)
        else:
            logger.error("Unexpected response format for authorization servers: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return servers


def get_authorization_server_claims(domain_url, api_token, server_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authorization server claims for server_id=%s.", server_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authorizationServers/{server_id}/claims?limit={limit}"

    claims = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching claims for server {server_id}")
        if data is None:
            break

        if isinstance(data, list):
            claims.extend(data)
        else:
            logger.error("Unexpected response format for claims: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return claims


def get_authorization_server_scopes(domain_url, api_token, server_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authorization server scopes for server_id=%s.", server_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authorizationServers/{server_id}/scopes?limit={limit}"

    scopes = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching scopes for server {server_id}")
        if data is None:
            break

        if isinstance(data, list):
            scopes.extend(data)
        else:
            logger.error("Unexpected response format for scopes: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return scopes


def get_authorization_server_policies(domain_url, api_token, server_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authorization server policies for server_id=%s.", server_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authorizationServers/{server_id}/policies?limit={limit}"

    policies = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching policies for server {server_id}")
        if data is None:
            break

        if isinstance(data, list):
            policies.extend(data)
        else:
            logger.error("Unexpected response format for policies: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return policies


def get_authorization_server_policy_rules(domain_url, api_token, server_id, policy_id, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching authorization server policy rules for policy_id=%s.", policy_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/authorizationServers/{server_id}/policies/{policy_id}/rules?limit={limit}"

    rules = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching rules for policy {policy_id}")
        if data is None:
            break

        if isinstance(data, list):
            rules.extend(data)
        else:
            logger.error("Unexpected response format for policy rules: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return rules
