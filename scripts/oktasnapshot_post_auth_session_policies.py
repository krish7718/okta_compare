import logging

from scripts.extract_post_auth_session_policies import (
    get_post_auth_session_policies,
    get_post_auth_session_policy_rules,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_post_auth_session_policies_view(domain_url, api_token):
    logger.info("Fetching post-auth session policies for OktaView.")
    policies = get_post_auth_session_policies(domain_url, api_token) or []
    policy_rows = []
    rule_rows = []
    for policy in policies:
        policy_id = policy.get("id")
        policy_name = policy.get("name")
        policy_rows.append({
            "Policy ID": policy_id,
            "Policy Name": policy_name,
            "Status": policy.get("status"),
            "Priority": policy.get("priority"),
            "Description": policy.get("description"),
            "Conditions": policy.get("conditions"),
            "Settings": policy.get("settings"),
        })
        for rule in get_post_auth_session_policy_rules(domain_url, api_token, policy_id) or []:
            rule_rows.append({
                "Policy Name": policy_name,
                "Rule ID": rule.get("id"),
                "Rule Name": rule.get("name"),
                "Status": rule.get("status"),
                "Priority": rule.get("priority"),
                "Conditions": rule.get("conditions"),
                "Actions": rule.get("actions"),
                "Settings": rule.get("settings"),
            })
    return policy_rows, rule_rows
