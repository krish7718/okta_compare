import json

from scripts.extract_brands import get_brands, get_brand_email_templates

_SKIP_KEYS = {"id", "_links", "links", "created", "createdBy", "lastUpdated", "lastUpdatedBy", "_embedded"}


def _brand_key(brand):
    return brand.get("name") or brand.get("id")


def _sanitize(value):
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _SKIP_KEYS}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def _signature_list(items):
    normalized = [_sanitize(item) for item in items or []]
    return json.dumps(sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True, default=str)), sort_keys=True, default=str)


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


def _customization_signature(customizations):
    normalized = []
    for customization in customizations or []:
        subject, body = _extract_subject_body(customization)
        normalized.append({
            "subject": subject,
            "body": body,
        })
    return _signature_list(normalized)


def compare_brand_email_templates(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare brand email templates for matching brand names only.
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
        templatesA = get_brand_email_templates(baseA, envA_token, brandA.get("id"), limit=limit)
        templatesB = get_brand_email_templates(baseB, envB_token, brandB.get("id"), limit=limit)

        for template_name, customizationsA in templatesA.items():
            if template_name not in templatesB:
                diffs.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": template_name,
                    "Env A Value": "Exists",
                    "Env B Value": "Missing",
                    "Difference Type": "Missing in Env B",
                    "Impact": "Email Branding",
                    "Recommended Action": f"Create email template '{template_name}' for brand '{name}' in Env B",
                    "Priority": "🔴 Critical"
                })
                continue

            customizationsB = templatesB.get(template_name, [])
            if _customization_signature(customizationsA) != _customization_signature(customizationsB):
                diffs.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": template_name,
                    "Env A Value": "Didn't match",
                    "Env B Value": "Didn't match",
                    "Difference Type": "Mismatch",
                    "Impact": "Email Branding Drift",
                    "Recommended Action": f"Align email template '{template_name}' for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": template_name,
                    "Value": "Match"
                })

        for template_name in templatesB:
            if template_name not in templatesA:
                diffs.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": template_name,
                    "Env A Value": "Missing",
                    "Env B Value": "Exists",
                    "Difference Type": "Extra in Env B",
                    "Impact": "Unexpected Template",
                    "Recommended Action": f"Review extra email template '{template_name}' for brand '{name}' in Env B",
                    "Priority": "🟡 Low"
                })

    return diffs, matches
