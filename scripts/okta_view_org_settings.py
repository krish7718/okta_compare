import logging

from scripts.okta_view_utils import ensure_domain_str, get_json

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


def _get_user_email(base, api_token, user_id):
    if not user_id:
        return None
    url = f"{base}/api/v1/users/{user_id}"
    data = get_json(url, _headers(api_token), "Error fetching user email")
    if not isinstance(data, dict):
        return None
    return data.get("email")


def _get_contact_email(base, api_token, contact_type):
    url = f"{base}/api/v1/org/contacts/{contact_type}"
    data = get_json(url, _headers(api_token), f"Error fetching {contact_type} contact")
    if not isinstance(data, dict):
        return None
    return _get_user_email(base, api_token, data.get("userId"))


def get_org_settings(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching org general settings for OktaView.")
    data = get_json(f"{base}/api/v1/org", _headers(api_token), "Error fetching org settings")
    if not isinstance(data, dict):
        return None
    return {
        "Address1": data.get("address1"),
        "Address2": data.get("address2"),
        "City": data.get("city"),
        "Company Name": data.get("companyName"),
        "Country": data.get("country"),
        "End User Support Help URL": data.get("endUserSupportHelpURL"),
        "Phone Number": data.get("phoneNumber"),
        "Postal Code": data.get("postalCode"),
        "State": data.get("state"),
        "Support Phone Number": data.get("supportPhoneNumber"),
        "Website": data.get("website"),
        "ID": data.get("id"),
        "Created": data.get("created"),
        "Last Updated": data.get("lastUpdated"),
        "Expires At": data.get("expiresAt"),
        "Status": data.get("status"),
        "Subdomain": data.get("subdomain"),
        "Billing Contact Email": _get_contact_email(base, api_token, "billing"),
        "Technical Contact Email": _get_contact_email(base, api_token, "technical"),
    }
