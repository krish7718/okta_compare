import json
import logging

from scripts.extract_attack_protection import get_attack_protection_bundle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _append_settings_rows(rows, component, obj_name, payload):
    if payload is None:
        rows.append({
            "Component": component,
            "Object": obj_name,
            "Field": "Settings",
            "Value": "Not Available",
        })
        return

    if isinstance(payload, dict):
        for key, value in payload.items():
            rows.append({
                "Component": component,
                "Object": obj_name,
                "Field": key,
                "Value": json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else value,
            })
        return

    rows.append({
        "Component": component,
        "Object": obj_name,
        "Field": "Value",
        "Value": payload,
    })


def get_attack_protection_view(domain_url, api_token):
    logger.info("Fetching attack protection for OktaView.")
    bundle = get_attack_protection_bundle(domain_url, api_token) or {}
    rows = []

    _append_settings_rows(rows, "Authenticator Settings", "Authenticator Settings", bundle.get("authenticator_settings"))
    _append_settings_rows(rows, "User Lockout Settings", "User Lockout Settings", bundle.get("user_lockout_settings"))
    _append_settings_rows(rows, "Bot Protection Configuration", "Bot Protection Configuration", bundle.get("bot_protection_configuration"))
    _append_settings_rows(rows, "Org-wide CAPTCHA Settings", "Org-wide CAPTCHA Settings", bundle.get("org_captcha_settings"))

    for behavior in bundle.get("behavior_detection_rules") or []:
        name = behavior.get("name") or behavior.get("type") or behavior.get("id") or "Behavior Rule"
        _append_settings_rows(rows, "Behavior Detection Rules", name, behavior)

    for captcha in bundle.get("captchas") or []:
        name = captcha.get("name") or captcha.get("type") or captcha.get("id") or "CAPTCHA"
        _append_settings_rows(rows, "CAPTCHAs", name, captcha)

    return rows
