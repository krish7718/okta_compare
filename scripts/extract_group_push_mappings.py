import logging
import requests

from scripts.extract_applications import get_applications

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _ensure_domain_str(domain_url):
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def _headers(api_token):
    return {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }


def _group_push_apps(domain_url, api_token, limit=200):
    apps = get_applications(domain_url, api_token, limit=limit) or []
    return [app for app in apps if "GROUP_PUSH" in (app.get("features") or [])]


def get_group_push_mappings_for_app(domain_url, api_token, app_id, limit=200):
    if not app_id:
        return []

    logger.info("Fetching group push mappings for app_id=%s.", app_id)
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/apps/{app_id}/group-push/mappings?limit={limit}"
    headers = _headers(api_token)

    mappings = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            logger.error("Error fetching group push mappings for %s: %s %s", app_id, resp.status_code, resp.text)
            break

        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for group push mappings (app %s)", app_id)
            break

        if isinstance(data, list):
            mappings.extend(data)
        else:
            logger.error("Unexpected response format for group push mappings: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return mappings


def get_group_push_mapping_by_id(domain_url, api_token, app_id, mapping_id):
    if not app_id or not mapping_id:
        return None

    logger.info("Fetching group push mapping detail for app_id=%s mapping_id=%s.", app_id, mapping_id)
    base = _ensure_domain_str(domain_url).rstrip("/")
    url = f"{base}/api/v1/apps/{app_id}/group-push/mappings/{mapping_id}"
    resp = requests.get(url, headers=_headers(api_token))
    if resp.status_code != 200:
        logger.error(
            "Error fetching group push mapping detail for %s/%s: %s %s",
            app_id,
            mapping_id,
            resp.status_code,
            resp.text,
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("Invalid JSON received for group push mapping detail (%s/%s)", app_id, mapping_id)
        return None

    return data if isinstance(data, dict) else None


def get_group_push_mappings(domain_url, api_token, limit=200):
    rows = []
    for app in _group_push_apps(domain_url, api_token, limit=limit):
        app_id = app.get("id")
        mappings = get_group_push_mappings_for_app(domain_url, api_token, app_id, limit=limit) or []
        for mapping in mappings:
            mapping_id = mapping.get("id")
            detail = get_group_push_mapping_by_id(domain_url, api_token, app_id, mapping_id) or {}
            combined = dict(mapping)
            combined.update(detail)
            combined["_app"] = {
                "id": app_id,
                "label": app.get("label"),
                "name": app.get("name"),
                "signOnMode": app.get("signOnMode"),
            }
            rows.append(combined)
    return rows
