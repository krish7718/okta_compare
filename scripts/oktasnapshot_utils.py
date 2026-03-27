import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def ensure_domain_str(domain_url):
    """Ensure domain_url is a valid HTTPS string."""
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(("http://", "https://")) else f"https://{domain_url}"


def _request_label(error_label):
    label = str(error_label or "").strip()
    if label.lower().startswith("error fetching "):
        label = label[len("Error fetching "):]
    if not label:
        label = "resource"
    return label


def get_json(url, headers, error_label):
    request_label = _request_label(error_label)
    logger.info("Fetching %s: requesting %s", request_label, url)
    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as exc:
        logger.error("%s: request failed for %s (%s)", error_label, url, exc)
        return None
    if resp.status_code != 200:
        logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
        return None
    try:
        return resp.json()
    except ValueError:
        logger.error("Invalid JSON received for %s", error_label)
        return None


def _next_link(headers):
    link = headers.get("Link")
    if link:
        for part in link.split(","):
            if 'rel="next"' in part:
                return part.split(";")[0].strip().strip("<>")
    return None


def get_paginated(url, headers, error_label):
    items = []
    page = 0
    seen_urls = set()
    request_label = _request_label(error_label)
    while url:
        if url in seen_urls:
            logger.warning("%s: detected repeated pagination URL, stopping loop at %s", error_label, url)
            break
        seen_urls.add(url)
        page += 1
        logger.info("Fetching %s: requesting page %s from %s", request_label, page, url)
        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            logger.error("%s: request failed on page %s (%s)", error_label, page, exc)
            break
        if resp.status_code != 200:
            logger.error("%s: %s %s", error_label, resp.status_code, resp.text)
            break
        try:
            data = resp.json()
        except ValueError:
            logger.error("Invalid JSON received for %s", error_label)
            break
        if not isinstance(data, list):
            logger.error("Unexpected response format for %s: %s", error_label, type(data))
            break
        items.extend(data)
        logger.info(
            "Fetching %s: fetched %s item(s) from page %s; accumulated total=%s",
            request_label,
            len(data),
            page,
            len(items),
        )
        url = _next_link(resp.headers)
        if url:
            logger.info("Fetching %s: pagination continues after page %s", request_label, page)
        else:
            logger.info("Fetching %s: pagination complete after %s page(s)", request_label, page)
    return items
