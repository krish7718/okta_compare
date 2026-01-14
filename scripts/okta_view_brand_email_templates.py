import logging

from scripts.extract_brands import get_brands, get_brand_email_templates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _extract_subject_body(customization):
    if not isinstance(customization, dict):
        return None, None
    subject = customization.get("subject")
    body = customization.get("body") or customization.get("htmlBody")

    content = customization.get("content")
    if isinstance(content, dict):
        subject = subject or content.get("subject")
        body = body or content.get("body") or content.get("htmlBody")

    translations = customization.get("translations")
    if isinstance(translations, list) and translations:
        for translation in translations:
            if not isinstance(translation, dict):
                continue
            subject = subject or translation.get("subject")
            body = body or translation.get("body") or translation.get("htmlBody")

    return subject, body


def get_brand_email_templates_view(domain_url, api_token):
    logger.info("Fetching brand email templates for OktaView.")
    brands = get_brands(domain_url, api_token) or []
    rows = []
    for brand in brands:
        brand_id = brand.get("id")
        brand_name = brand.get("name")
        templates_bundle = get_brand_email_templates(domain_url, api_token, brand_id) or {}
        customizations_map = templates_bundle.get("customizations") or {}
        defaults_map = templates_bundle.get("defaults") or {}

        for template_name, customizations in customizations_map.items():
            if not customizations:
                default_content = defaults_map.get(template_name) or {}
                subject = default_content.get("subject")
                body = default_content.get("body") or default_content.get("htmlBody")
                rows.append({
                    "Brand Name": brand_name,
                    "Template Name": template_name,
                    "Subject": subject or "",
                    "Body": body or "",
                })
                continue
            for customization in customizations:
                subject, body = _extract_subject_body(customization)
                rows.append({
                    "Brand Name": brand_name,
                    "Template Name": template_name,
                    "Subject": subject or "",
                    "Body": body or "",
                })
    return rows
