import logging
import requests
from urllib.parse import quote

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _ensure_domain_str(domain_url):
    """Ensure domain_url is a valid HTTPS string."""
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def _get_json(url, headers, error_label):
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
        return None, resp
    try:
        return resp.json(), resp
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None, resp


def get_brands(domain_url, api_token, limit=200):
    """
    Fetch all brands.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching brands.")
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/brands?limit={limit}"

    brands = []
    while url:
        data, resp = _get_json(url, headers, "Error fetching brands")
        if data is None:
            break

        if isinstance(data, list):
            brands.extend(data)
        else:
            logger.error("Unexpected response format for brands: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return brands


def get_brand_themes(domain_url, api_token, brand_id, limit=200):
    """
    Fetch themes for a given brand.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching themes for brand_id=%s.", brand_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/brands/{brand_id}/themes?limit={limit}"

    themes = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching themes for brand {brand_id}")
        if data is None:
            break

        if isinstance(data, list):
            themes.extend(data)
        else:
            logger.error("Unexpected response format for themes: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    return themes


def get_brand_pages(domain_url, api_token, brand_id):
    """
    Fetch sign-in and error page settings for a brand.
    Returns dict with keys: sign_in, error.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching brand pages for brand_id=%s.", brand_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")

    sign_in_url = f"{base}/api/v1/brands/{brand_id}/pages/sign-in/customized"
    error_url = f"{base}/api/v1/brands/{brand_id}/pages/error/customized"

    sign_in, _ = _get_json(sign_in_url, headers, f"Error fetching sign-in page for brand {brand_id}")
    error, _ = _get_json(error_url, headers, f"Error fetching error page for brand {brand_id}")

    return {
        "sign_in": sign_in or {},
        "error": error or {},
    }


def get_brand_email_templates(domain_url, api_token, brand_id, limit=200):
    """
    Fetch email templates and their customizations for a brand.
    Returns dict mapping template_name -> customizations list.
    """
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }

    logger.info("Fetching email templates for brand_id=%s.", brand_id)
    domain_url = _ensure_domain_str(domain_url)
    base = domain_url.rstrip("/")
    url = f"{base}/api/v1/brands/{brand_id}/templates/email?limit={limit}"

    templates = []
    while url:
        data, resp = _get_json(url, headers, f"Error fetching email templates for brand {brand_id}")
        if data is None:
            break

        if isinstance(data, list):
            templates.extend(data)
        else:
            logger.error("Unexpected response format for email templates: %s", type(data))
            break

        next_link = resp.headers.get("Link")
        if next_link and 'rel="next"' in next_link:
            url = next_link.split(";")[0].strip("<>")
        else:
            url = None

    template_customizations = {}
    for template in templates:
        name = template.get("name") or template.get("templateName") or template.get("id")
        if not name:
            continue

        safe_name = quote(str(name), safe="")
        cust_url = f"{base}/api/v1/brands/{brand_id}/templates/email/{safe_name}/customizations?limit={limit}"
        data, _ = _get_json(
            cust_url,
            headers,
            f"Error fetching email customizations for template {name} (brand {brand_id})",
        )
        if isinstance(data, list):
            template_customizations[name] = data
        elif data is None:
            template_customizations[name] = []
        else:
            logger.error("Unexpected response format for email customizations: %s", type(data))
            template_customizations[name] = []

    return template_customizations
