import json
import logging

from scripts.extract_brands import get_brands, get_brand_pages

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _brand_key(brand):
    return brand.get("name") or brand.get("id")


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature(value):
    return json.dumps(_sanitize(value), sort_keys=True, default=str)


def _widget_customizations_signature(page):
    customizations = (page or {}).get("widgetCustomizations") or {}
    return json.dumps(_sanitize(customizations), sort_keys=True, default=str)


def compare_brand_pages(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare brand pages (sign-in and error) for matching brand names only.
    Returns (diffs, matches).
    """
    baseA = f"https://{envA_domain}"
    baseB = f"https://{envB_domain}"

    brandsA = get_brands(baseA, envA_token, limit=limit) or []
    brandsB = get_brands(baseB, envB_token, limit=limit) or []

    diffs = []
    matches = []

    dictA = {_brand_key(b): b for b in brandsA}
    dictB = {_brand_key(b): b for b in brandsB}

    for name, brandA in dictA.items():
        if name not in dictB:
            continue

        brandB = dictB[name]
        pagesA = get_brand_pages(baseA, envA_token, brandA.get("id"))
        pagesB = get_brand_pages(baseB, envB_token, brandB.get("id"))

        for page_key, label in (("sign_in", "Sign-In Page"), ("error", "Error Page")):
            if page_key == "sign_in":
                contentA = (pagesA.get(page_key, {}) or {}).get("pageContent")
                contentB = (pagesB.get(page_key, {}) or {}).get("pageContent")
                if _widget_customizations_signature(pagesA.get(page_key, {})) != _widget_customizations_signature(
                    pagesB.get(page_key, {})
                ):
                    logger.warning(
                        "Sign-in widget customizations mismatch for brand '%s'.",
                        name,
                    )
                if contentA != contentB:
                    diffs.append({
                        "Category": "Brand Pages",
                        "Object": name,
                        "Attribute": f"{label} HTML",
                        "Env A Value": "Different",
                        "Env B Value": "Different",
                        "Difference Type": "Mismatch",
                        "Impact": "User Experience",
                        "Recommended Action": f"Align {label.lower()} HTML for brand '{name}'",
                        "Priority": "🟠 Medium"
                    })
                else:
                    matches.append({
                        "Category": "Brand Pages",
                        "Object": name,
                        "Attribute": f"{label} HTML",
                        "Value": "Match"
                    })
                continue

            sigA = _signature(pagesA.get(page_key, {}))
            sigB = _signature(pagesB.get(page_key, {}))

            if sigA != sigB:
                diffs.append({
                    "Category": "Brand Pages",
                    "Object": name,
                    "Attribute": label,
                    "Env A Value": "Different",
                    "Env B Value": "Different",
                    "Difference Type": "Mismatch",
                    "Impact": "User Experience",
                    "Recommended Action": f"Align {label.lower()} settings for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Pages",
                    "Object": name,
                    "Attribute": label,
                    "Value": "Match"
                })

    return diffs, matches
