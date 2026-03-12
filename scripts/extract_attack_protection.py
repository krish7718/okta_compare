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


def _get_paginated(url, headers, error_label):
    items = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
            break
        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for %s", error_label)
            break
        if isinstance(data, list):
            items.extend(data)
        else:
            logger.error("Unexpected response format for %s: %s", error_label, type(data))
            break
        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None
    return items


def get_attack_protection_bundle(domain_url, api_token, limit=200):
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    base = _ensure_domain_str(domain_url).rstrip("/")

    logger.info("Fetching attack protection bundle.")

    authenticator_settings = _get_json(
        f"{base}/attack-protection/api/v1/authenticator-settings",
        headers,
        "Error fetching attack protection authenticator settings",
    )
    user_lockout_settings = _get_json(
        f"{base}/attack-protection/api/v1/user-lockout-settings",
        headers,
        "Error fetching attack protection user lockout settings",
    )
    bot_protection = _get_json(
        f"{base}/api/v1/bot-protection/configuration",
        headers,
        "Error fetching bot protection configuration",
    )
    org_captcha = _get_json(
        f"{base}/api/v1/org/captcha",
        headers,
        "Error fetching org-wide captcha settings",
    )

    behaviors = _get_paginated(
        f"{base}/api/v1/behaviors?limit={limit}",
        headers,
        "Error fetching behavior detection rules",
    )
    behavior_details = []
    for behavior in behaviors:
        behavior_id = behavior.get("id")
        if not behavior_id:
            behavior_details.append(behavior)
            continue
        detail = _get_json(
            f"{base}/api/v1/behaviors/{behavior_id}",
            headers,
            f"Error fetching behavior detection rule {behavior_id}",
        )
        behavior_details.append(detail if isinstance(detail, dict) else behavior)

    captchas = _get_paginated(
        f"{base}/api/v1/captchas?limit={limit}",
        headers,
        "Error fetching captchas",
    )
    captcha_details = []
    for captcha in captchas:
        captcha_id = captcha.get("id")
        if not captcha_id:
            captcha_details.append(captcha)
            continue
        detail = _get_json(
            f"{base}/api/v1/captchas/{captcha_id}",
            headers,
            f"Error fetching captcha {captcha_id}",
        )
        captcha_details.append(detail if isinstance(detail, dict) else captcha)

    return {
        "authenticator_settings": authenticator_settings,
        "user_lockout_settings": user_lockout_settings,
        "bot_protection_configuration": bot_protection,
        "org_captcha_settings": org_captcha,
        "behavior_detection_rules": behavior_details,
        "captchas": captcha_details,
    }
