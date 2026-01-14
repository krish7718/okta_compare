import logging

from scripts.okta_view_utils import ensure_domain_str, get_paginated

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
    return get_paginated(url, _headers(api_token), "Error fetching MFA enrollment policy rules") or []


def get_mfa_enrollment_policies(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching MFA enrollment policies for OktaView.")
    url = f"{base}/api/v1/policies?type=MFA_ENROLL"
    policies = get_paginated(url, _headers(api_token), "Error fetching MFA enrollment policies") or []

    policy_rows = []
    rule_rows = []

    for policy in policies:
        policy_id = policy.get("id")
        rules = _get_rules(base, api_token, policy_id)
        policy_rows.append({
            "ID": policy_id,
            "Status": policy.get("status"),
            "Name": policy.get("name"),
            "Priority": policy.get("priority"),
            "Conditions": policy.get("conditions"),
            "Settings": policy.get("settings"),
        })

        for rule in rules:
            conditions = rule.get("conditions", {}) or {}
            rule_rows.append({
                "Policy ID": policy_id,
                "Policy Name": policy.get("name"),
                "Rule ID": rule.get("id"),
                "Rule Name": rule.get("name"),
                "Status": rule.get("status"),
                "Priority": rule.get("priority"),
                "Conditions People": conditions.get("people", {}),
                "Conditions Network": conditions.get("network", {}),
                "Conditions AuthContext": conditions.get("authContext", {}),
                "Conditions Risk": conditions.get("risk", {}),
                "Conditions RiskScore": conditions.get("riskScore", {}),
                "Conditions IdentityProvider": conditions.get("identityProvider", {}),
                "Actions": rule.get("actions", {}),
            })

    return policy_rows, rule_rows
