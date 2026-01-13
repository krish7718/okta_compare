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


def _admin_domain(domain_url):
    base = _ensure_domain_str(domain_url)
    if "://" not in base:
        base = f"https://{base}"
    scheme, rest = base.split("://", 1)
    host = rest.split("/", 1)[0]
    if host.endswith("-admin.oktapreview.com") or host.endswith("-admin.okta.com"):
        return f"{scheme}://{host}"
    if host.endswith(".oktapreview.com"):
        sub = host.split(".")[0]
        return f"{scheme}://{sub}-admin.oktapreview.com"
    if host.endswith(".okta.com"):
        sub = host.split(".")[0]
        return f"{scheme}://{sub}-admin.okta.com"
    return f"{scheme}://{host}"


def _get_json(url, headers, error_label):
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
        return None
    try:
        return resp.json()
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None


def get_security_general_settings(domain_url, api_token):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    base = _ensure_domain_str(domain_url).rstrip("/")
    admin_base = _admin_domain(domain_url).rstrip("/")
    logger.info("Fetching security general settings.")
    return {
        "threats_configuration": _get_json(
            f"{base}/api/v1/threats/configuration",
            headers,
            "Error fetching threats configuration",
        ),
        "threatinsight": _get_json(
            f"{base}/api/v1/internal/threatInsightDataCollection",
            headers,
            "Error fetching ThreatInsight settings",
        ),
        "security_notifications": _get_json(
            f"{admin_base}/api/internal/org/settings/security-notification-settings",
            headers,
            "Error fetching security notification settings",
        ),
        "captcha": _get_json(
            f"{base}/api/v1/org/captcha",
            headers,
            "Error fetching captcha settings",
        ),
        "user_enumeration": _get_json(
            f"{admin_base}/api/internal/org/settings/user-enumeration-settings",
            headers,
            "Error fetching user enumeration settings",
        ),
        "user_lockout": _get_json(
            f"{base}/attack-protection/api/v1/user-lockout-settings",
            headers,
            "Error fetching user lockout settings",
        ),
        "authenticator_settings": _get_json(
            f"{base}/attack-protection/api/v1/authenticator-settings",
            headers,
            "Error fetching authenticator settings",
        ),
    }
