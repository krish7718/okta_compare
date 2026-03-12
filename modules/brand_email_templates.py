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


def _template_rows(customizations, default_content):
    rows = []
    for customization in customizations or []:
        subject, body = _extract_subject_body(customization)
        rows.append({
            "subject": subject or "",
            "body": body or "",
        })

    if rows:
        return rows

    subject, body = _extract_subject_body(default_content)
    return [{
        "subject": subject or "",
        "body": body or "",
    }]


def _template_subject_signature(rows):
    return _signature_list([{"subject": row.get("subject", "")} for row in rows or []])


def _template_body_signature(rows):
    return _signature_list([{"body": row.get("body", "")} for row in rows or []])


def _template_preview(rows, key):
    values = [str((row or {}).get(key) or "") for row in rows or []]
    values = [value for value in values if value]
    if not values:
        return "<empty>"
    if len(values) == 1:
        return values[0]
    return f"{len(values)} variants"


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
        templatesA = get_brand_email_templates(baseA, envA_token, brandA.get("id"), limit=limit) or {}
        templatesB = get_brand_email_templates(baseB, envB_token, brandB.get("id"), limit=limit) or {}
        customizationsA_map = templatesA.get("customizations") or {}
        customizationsB_map = templatesB.get("customizations") or {}
        defaultsA_map = templatesA.get("defaults") or {}
        defaultsB_map = templatesB.get("defaults") or {}

        for template_name in customizationsA_map:
            if template_name not in customizationsB_map:
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

            customizationsA = customizationsA_map.get(template_name, [])
            customizationsB = customizationsB_map.get(template_name, [])
            defaultA = defaultsA_map.get(template_name)
            defaultB = defaultsB_map.get(template_name)
            rowsA = _template_rows(customizationsA, defaultA)
            rowsB = _template_rows(customizationsB, defaultB)

            if _template_subject_signature(rowsA) != _template_subject_signature(rowsB):
                diffs.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": f"{template_name} / Subject",
                    "Env A Value": _template_preview(rowsA, "subject"),
                    "Env B Value": _template_preview(rowsB, "subject"),
                    "Difference Type": "Mismatch",
                    "Impact": "Email Branding Drift",
                    "Recommended Action": f"Align subject for email template '{template_name}' for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": f"{template_name} / Subject",
                    "Value": "Match"
                })

            if _template_body_signature(rowsA) != _template_body_signature(rowsB):
                diffs.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": f"{template_name} / Body",
                    "Env A Value": _template_preview(rowsA, "body"),
                    "Env B Value": _template_preview(rowsB, "body"),
                    "Difference Type": "Mismatch",
                    "Impact": "Email Branding Drift",
                    "Recommended Action": f"Align body for email template '{template_name}' for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Email Templates",
                    "Object": name,
                    "Attribute": f"{template_name} / Body",
                    "Value": "Match"
                })

        for template_name in customizationsB_map:
            if template_name not in customizationsA_map:
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
