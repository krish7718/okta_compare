import logging

from scripts.okta_view_utils import ensure_domain_str, get_paginated, get_json

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


def _get_rules(base, api_token, policy_id):
    url = f"{base}/api/v1/policies/{policy_id}/rules"
    return get_paginated(url, _headers(api_token), "Error fetching password policy rules") or []


def _settings_to_string(settings):
    if not isinstance(settings, dict):
        return ""
    return ", ".join([f"{k}: {v}" for k, v in settings.items()])


def get_password_policies(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching password policies for OktaView.")
    url = f"{base}/api/v1/policies?type=PASSWORD"
    policies = get_paginated(url, _headers(api_token), "Error fetching password policies") or []

    policy_rows = []
    rule_rows = []

    for policy in policies:
        policy_id = policy.get("id")
        rules = _get_rules(base, api_token, policy_id)
        policy_rows.append({
            "ID": policy_id,
            "Status": policy.get("status"),
            "Name": policy.get("name"),
            "Description": policy.get("description"),
            "Priority": policy.get("priority"),
            "Provider": (policy.get("provider", {}) or {}).get("type"),
            "Complexity Settings": _settings_to_string((policy.get("settings", {}) or {}).get("complexity", {})),
            "Lockout Settings": _settings_to_string((policy.get("settings", {}) or {}).get("lockout", {})),
            "Rules": ", ".join([r.get("name") for r in rules if r.get("name")]),
        })

        for rule in rules:
            rule_rows.append({
                "Policy ID": policy_id,
                "Policy Name": policy.get("name"),
                "Rule ID": rule.get("id"),
                "Rule Name": rule.get("name"),
                "Status": rule.get("status"),
                "Priority": rule.get("priority"),
                "Conditions People": (rule.get("conditions", {}) or {}).get("people", {}),
                "Conditions Network": (rule.get("conditions", {}) or {}).get("network", {}),
                "Actions": rule.get("actions", {}),
            })

    return policy_rows, rule_rows
