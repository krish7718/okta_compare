import logging

from scripts.extract_realms import get_realms, get_realm_assignments

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_realms_view(domain_url, api_token):
    logger.info("Fetching realms for OktaView.")
    realms = get_realms(domain_url, api_token) or []
    rows = []
    for realm in realms:
        rows.append({
            "Realm ID": realm.get("id"),
            "Name": realm.get("name") or realm.get("label") or realm.get("displayName"),
            "Description": realm.get("description"),
            "Status": realm.get("status"),
            "Created": realm.get("created"),
            "Last Updated": realm.get("lastUpdated"),
        })
    return rows


def get_realm_assignments_view(domain_url, api_token):
    logger.info("Fetching realm assignments for OktaView.")
    assignments = get_realm_assignments(domain_url, api_token) or []
    rows = []
    for assignment in assignments:
        rows.append({
            "Assignment ID": assignment.get("id"),
            "Name": assignment.get("name"),
            "Status": assignment.get("status"),
            "Is Default": assignment.get("isDefault"),
            "Priority": assignment.get("priority"),
            "Domains": assignment.get("domains"),
            "Conditions": assignment.get("conditions"),
            "Actions": assignment.get("actions"),
        })
    return rows
