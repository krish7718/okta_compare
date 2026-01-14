import logging

from scripts.extract_security_settings import get_security_general_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _enabled_label(value):
    if value is None:
        return "Not Available"
    return "Enabled" if bool(value) else "Not Enabled"


def _captcha_type(captcha):
    if not isinstance(captcha, dict):
        return "Not Available"
    captcha_id = captcha.get("captchaId")
    if captcha_id:
        return captcha_id
    return "None"


def _safe_value(value):
    return value if value is not None else "Not Available"


def _enabled_state(value):
    if value is None:
        return "Not Available"
    return "Enabled" if bool(value) else "Disabled"


def _enum_flow(flow):
    if not flow:
        return {"Authentication": "Not Available", "Recovery": "Not Available"}
    flow = str(flow).upper()
    if flow == "RECOVERY":
        return {"Authentication": "Disabled", "Recovery": "Enabled"}
    if flow == "AUTHENTICATION":
        return {"Authentication": "Enabled", "Recovery": "Disabled"}
    if flow == "BOTH":
        return {"Authentication": "Enabled", "Recovery": "Enabled"}
    return {"Authentication": "Not Available", "Recovery": "Not Available"}


def _threat_action_label(action):
    if action is None:
        return "Not Available"
    if action == "none":
        return "No action"
    if action == "log":
        return "Log authentication attempts from malicious IPs"
    if action == "block":
        return "Log and enforce security based on threat level"
    return str(action)


def _exclude_zones_label(zones):
    if zones is None:
        return "Not Available"
    if not zones:
        return "None"
    return ", ".join(zones)


def get_security_settings(domain_url, api_token):
    logger.info("Fetching security settings for OktaView.")
    settings = get_security_general_settings(domain_url, api_token) or {}

    notifications = settings.get("security_notifications") or {}
    threats = settings.get("threats_configuration") or {}
    threatinsight = settings.get("threatinsight") or {}
    captcha = settings.get("captcha") or {}
    user_enum = settings.get("user_enumeration") or {}
    user_lockout = settings.get("user_lockout") or {}
    authenticator = settings.get("authenticator_settings") or {}

    enum_flow = _enum_flow(user_enum.get("userEnumerationSettingFlow") if isinstance(user_enum, dict) else None)

    rows = [
        {"Setting": "Security notification emails", "Value": ""},
        {
            "Setting": "New sign-on notification email",
            "Value": _enabled_label(notifications.get("sendEmailForNewDeviceEnabled")),
        },
        {
            "Setting": "Password changed notification email",
            "Value": _enabled_label(notifications.get("sendEmailForPasswordChangedEnabled")),
        },
        {
            "Setting": "Authenticator enrolled notification email",
            "Value": _enabled_label(notifications.get("sendEmailForFactorEnrollmentEnabled")),
        },
        {
            "Setting": "Authenticator reset notification email",
            "Value": _enabled_label(notifications.get("sendEmailForFactorResetEnabled")),
        },
        {
            "Setting": "Report suspicious activity via email",
            "Value": _enabled_label(notifications.get("reportSuspiciousActivityEnabled")),
        },
        {"Setting": "CAPTCHA integration", "Value": ""},
        {"Setting": "CAPTCHA type", "Value": _captcha_type(captcha)},
        {"Setting": "User enumeration prevention", "Value": ""},
        {"Setting": "Enable for Authentication", "Value": enum_flow["Authentication"]},
        {"Setting": "Enable for Recovery", "Value": enum_flow["Recovery"]},
        {
            "Setting": "Require verification with unknown device",
            "Value": _enabled_state(user_enum.get("permitUserEnumerationWithUnknownDeviceEnabled")),
        },
        {"Setting": "Protect against password-based attacks", "Value": ""},
        {
            "Setting": "Require possession factor before password during MFA",
            "Value": _enabled_state(authenticator.get("verifyKnowledgeSecondWhen2faRequired")),
        },
        {
            "Setting": "Block suspicious password attempts from unknown devices",
            "Value": _enabled_state(user_lockout.get("preventBruteForceLockoutFromUnknownDevices")),
        },
        {"Setting": "Okta ThreatInsight settings", "Value": ""},
        {
            "Setting": "Action",
            "Value": _threat_action_label(threats.get("action") if isinstance(threats, dict) else None),
        },
        {
            "Setting": "Exempt Zones",
            "Value": _exclude_zones_label(threats.get("excludeZones") if isinstance(threats, dict) else None),
        },
        {
            "Setting": "Data Collection Enabled",
            "Value": _enabled_state(threatinsight.get("dataCollectionEnabled")),
        },
    ]

    return rows
