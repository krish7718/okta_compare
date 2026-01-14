import json
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


def _get_group_names(base, api_token, app_id):
    url = f"{base}/api/v1/apps/{app_id}/groups"
    groups = get_paginated(url, _headers(api_token), "Error fetching application groups") or []
    names = []
    for group in groups:
        profile = group.get("profile") or {}
        if profile.get("name"):
            names.append(profile.get("name"))
        elif group.get("name"):
            names.append(group.get("name"))
    return ", ".join(sorted(set(names)))


def _format_attribute_statements(statements):
    if not statements:
        return ""
    formatted = []
    for statement in statements:
        name = statement.get("name")
        stype = statement.get("type")
        ftype = statement.get("filterType")
        fvalue = statement.get("filterValue")
        parts = [p for p in (name, stype) if p]
        if ftype or fvalue:
            parts.append(f"{ftype or ''} {fvalue or ''}".strip())
        formatted.append(" - ".join(parts))
    return "; ".join(formatted)


def _format_saml_settings(app_settings, signon_settings):
    return {
        "Single Sign-On URL": signon_settings.get("ssoAcsUrl"),
        "IdP Issuer": signon_settings.get("idpIssuer"),
        "Audience": signon_settings.get("audience"),
        "Recipient": signon_settings.get("recipient"),
        "Destination": signon_settings.get("destination"),
        "Subject Name ID Template": signon_settings.get("subjectNameIdTemplate"),
        "Subject Name ID Format": signon_settings.get("subjectNameIdFormat"),
        "Response Signed": signon_settings.get("responseSigned"),
        "Assertion Signed": signon_settings.get("assertionSigned"),
        "Signature Algorithm": signon_settings.get("signatureAlgorithm"),
        "Digest Algorithm": signon_settings.get("digestAlgorithm"),
        "Honor Force Authn": signon_settings.get("honorForceAuthn"),
        "Authentication Context Class": signon_settings.get("authnContextClassRef"),
        "Request Compressed": signon_settings.get("requestCompressed"),
        "Signed Request Enabled": signon_settings.get("samlSignedRequestEnabled"),
        "Allow Multiple ACS Endpoints": signon_settings.get("allowMultipleAcsEndpoints"),
        "ACS Endpoints": ", ".join(signon_settings.get("acsEndpoints") or []),
        "Single Logout Enabled": (signon_settings.get("slo") or {}).get("enabled"),
        "Attribute Statements": _format_attribute_statements(signon_settings.get("attributeStatements")),
        "Audience Override": signon_settings.get("audienceOverride"),
        "Default Relay State": signon_settings.get("defaultRelayState"),
        "Recipient Override": signon_settings.get("recipientOverride"),
        "Destination Override": signon_settings.get("destinationOverride"),
        "SSO ACS URL Override": signon_settings.get("ssoAcsUrlOverride"),
    }


def _format_oidc_settings(app_settings, oauth_settings):
    return {
        "Client ID": oauth_settings.get("client_id") or oauth_settings.get("clientId"),
        "Token Endpoint Auth Method": oauth_settings.get("token_endpoint_auth_method"),
        "PKCE Required": oauth_settings.get("pkce_required"),
        "Redirect URIs": ", ".join(oauth_settings.get("redirect_uris") or []),
        "Post Logout Redirect URIs": ", ".join(oauth_settings.get("post_logout_redirect_uris") or []),
        "Grant Types": ", ".join(oauth_settings.get("grant_types") or []),
        "Response Types": ", ".join(oauth_settings.get("response_types") or []),
        "Application Type": oauth_settings.get("application_type"),
        "Initiate Login URI": oauth_settings.get("initiate_login_uri"),
        "Consent Method": oauth_settings.get("consent_method"),
        "Issuer Mode": oauth_settings.get("issuer_mode"),
        "Wildcard Redirect": oauth_settings.get("wildcard_redirect"),
        "DPoP Bound Access Tokens": oauth_settings.get("dpop_bound_access_tokens"),
        "Client URI": oauth_settings.get("client_uri"),
        "Logo URI": oauth_settings.get("logo_uri"),
    }


def _get_app_settings(app):
    sign_on_mode = app.get("signOnMode")
    settings = app.get("settings", {}) or {}
    app_settings = settings.get("app", {}) or {}
    if sign_on_mode == "BOOKMARK":
        visibility = app.get("visibility", {}) or {}
        app_links = visibility.get("appLinks") or {}
        user_name_template = (app.get("credentials", {}) or {}).get("userNameTemplate", {}) or {}
        return {
            "Bookmark URL": app_settings.get("url"),
            "App Links": ", ".join([name for name, enabled in app_links.items() if enabled]),
            "Username Template": user_name_template.get("template"),
        }
    if sign_on_mode == "SAML_2_0":
        return _format_saml_settings(app_settings, settings.get("signOn", {}) or {})
    if sign_on_mode == "OPENID_CONNECT":
        oauth_settings = settings.get("oauthClient", {}) or {}
        credentials = app.get("credentials", {}) or {}
        oauth_credentials = credentials.get("oauthClient", {}) or {}
        merged = {}
        merged.update(oauth_settings)
        merged.update(oauth_credentials)
        return _format_oidc_settings(app_settings, merged)
    if isinstance(app_settings, dict):
        return {str(k): v for k, v in app_settings.items()}
    return {"Application Settings": app_settings}


def _get_policy_name(base, api_token, policy_href, cache):
    if not policy_href:
        return ""
    policy_id = policy_href.split("/")[-1]
    if policy_id in cache:
        return cache[policy_id]
    data = get_json(f"{base}/api/v1/policies/{policy_id}", _headers(api_token), "Error fetching access policy")
    name = data.get("name") if isinstance(data, dict) else ""
    cache[policy_id] = name or ""
    return cache[policy_id]


def get_applications(domain_url, api_token):
    base = ensure_domain_str(domain_url).rstrip("/")
    logger.info("Fetching applications for OktaView.")
    url = f'{base}/api/v1/apps?filter=status eq "ACTIVE"&limit=200'
    apps = get_paginated(url, _headers(api_token), "Error fetching applications") or []
    rows = []
    policy_cache = {}
    for app in apps:
        credentials = app.get("credentials", {}) or {}
        user_name_template = credentials.get("userNameTemplate", {}) or {}
        sign_on_mode = app.get("signOnMode")
        links = app.get("_links", {}) or {}
        logo = (links.get("logo") or [{}])[0] or {}
        access_policy = links.get("accessPolicy", {}) or {}
        access_policy_name = _get_policy_name(base, api_token, access_policy.get("href"), policy_cache)
        settings = _get_app_settings(app)
        row = {}
        row["Name"] = app.get("label")
        row["Status"] = app.get("status")
        if sign_on_mode != "BOOKMARK":
            row["Type"] = sign_on_mode
        for key, value in settings.items():
            row[key] = value
        if sign_on_mode != "BOOKMARK":
            row["Okta Internal Name"] = app.get("name")
            row["Username Format"] = user_name_template.get("template")
            row["Logo"] = logo.get("href")
            row["Groups"] = _get_group_names(base, api_token, app.get("id"))
            row["Features"] = ", ".join(app.get("features") or [])
            row["Access Policy Name"] = access_policy_name
        rows.append(row)
    return rows
