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


def get_identity_providers(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching identity providers for OktaView.")
    url = f"{base}/api/v1/idps"
    idps = get_paginated(url, _headers(api_token), "Error fetching identity providers") or []
    results = []
    for idp in idps:
        protocol = idp.get("protocol", {}) or {}
        trust = protocol.get("credentials", {}).get("trust", {}) or {}
        results.append({
            "Name": idp.get("name"),
            "Type": idp.get("type"),
            "Protocol Type": protocol.get("type"),
            "SSO URL": protocol.get("endpoints", {}).get("sso", {}).get("url"),
            "Trust Issuer": trust.get("issuer"),
            "Trust Audience": trust.get("audience"),
            "Signing Key ID": protocol.get("credentials", {}).get("signing", {}).get("kid"),
            "Status": idp.get("status"),
            "Policy Max Clock Skew": idp.get("policy", {}).get("maxClockSkew"),
            "Policy Account Link Action": idp.get("policy", {}).get("accountLink", {}).get("action"),
            "Policy Username Template": idp.get("policy", {}).get("subject", {}).get("userNameTemplate", {}).get("template"),
            "Policy Provisioning Action": idp.get("policy", {}).get("provisioning", {}).get("action"),
        })
    return results
