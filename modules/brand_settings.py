from scripts.extract_brands import get_brands, get_brand_themes


def _brand_key(brand):
    return brand.get("name") or brand.get("id")


def _pick_theme(themes):
    if not themes:
        return {}
    for theme in themes:
        if theme.get("isDefault"):
            return theme
    return themes[0]


def _theme_settings(theme):
    return {
        "background_image": theme.get("backgroundImage") or "",
        "email_template_variant": theme.get("emailTemplateTouchPointVariant") or "",
        "end_user_dashboard_variant": theme.get("endUserDashboardTouchPointVariant") or "",
        "error_page_variant": theme.get("errorPageTouchPointVariant") or "",
        "favicon": theme.get("favicon") or "",
        "loading_page_variant": theme.get("loadingPageTouchPointVariant") or "",
        "logo": theme.get("logo") or "",
        "primary_color_contrast_hex": theme.get("primaryColorContrastHex") or "",
        "primary_color_hex": theme.get("primaryColorHex") or "",
        "secondary_color_contrast_hex": theme.get("secondaryColorContrastHex") or "",
        "secondary_color_hex": theme.get("secondaryColorHex") or "",
        "sign_in_page_variant": theme.get("signInPageTouchPointVariant") or "",
    }


def _brand_settings(brand):
    return {
        "name": brand.get("name") or "",
        "remove_powered_by_okta": brand.get("removePoweredByOkta"),
        "custom_privacy_policy_url": brand.get("customPrivacyPolicyUrl"),
        "agree_to_custom_privacy_policy": brand.get("agreeToCustomPrivacyPolicy"),
        "is_default": brand.get("isDefault"),
    }


def compare_brand_settings(envA_domain, envA_token, envB_domain, envB_token, limit=200):
    """
    Compare brand settings between Env A and Env B (theme logo/primary/secondary colors).
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
            diffs.append({
                "Category": "Brand Settings",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Exists",
                "Env B Value": "Missing",
                "Difference Type": "Missing in Env B",
                "Impact": "Branding",
                "Recommended Action": f"Create brand '{name}' in Env B",
                "Priority": "🔴 Critical"
            })
            continue

        brandB = dictB[name]
        themeA = _pick_theme(get_brand_themes(baseA, envA_token, brandA.get("id")) or [])
        themeB = _pick_theme(get_brand_themes(baseB, envB_token, brandB.get("id")) or [])

        settingsA = _brand_settings(brandA)
        settingsB = _brand_settings(brandB)
        for field, label in (
            ("name", "Brand Name"),
            ("remove_powered_by_okta", "Remove Powered By Okta"),
            ("custom_privacy_policy_url", "Custom Privacy Policy URL"),
            ("agree_to_custom_privacy_policy", "Agree To Custom Privacy Policy"),
            ("is_default", "Is Default"),
        ):
            if settingsA.get(field) != settingsB.get(field):
                diffs.append({
                    "Category": "Brand Settings",
                    "Object": name,
                    "Attribute": label,
                    "Env A Value": settingsA.get(field),
                    "Env B Value": settingsB.get(field),
                    "Difference Type": "Mismatch",
                    "Impact": "Branding Drift",
                    "Recommended Action": f"Align {label.lower()} for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Settings",
                    "Object": name,
                    "Attribute": label,
                    "Value": settingsA.get(field)
                })

        settingsA = _theme_settings(themeA)
        settingsB = _theme_settings(themeB)

        for field, label in (
            ("background_image", "Background Image"),
            ("email_template_variant", "Email Template Variant"),
            ("end_user_dashboard_variant", "End User Dashboard Variant"),
            ("error_page_variant", "Error Page Variant"),
            ("favicon", "Favicon"),
            ("loading_page_variant", "Loading Page Variant"),
            ("logo", "Logo"),
            ("primary_color_contrast_hex", "Primary Color Contrast Hex"),
            ("primary_color_hex", "Primary Color Hex"),
            ("secondary_color_contrast_hex", "Secondary Color Contrast Hex"),
            ("secondary_color_hex", "Secondary Color Hex"),
            ("sign_in_page_variant", "Sign-In Page Variant"),
        ):
            if settingsA.get(field) != settingsB.get(field):
                diffs.append({
                    "Category": "Brand Settings",
                    "Object": name,
                    "Attribute": label,
                    "Env A Value": settingsA.get(field) or "",
                    "Env B Value": settingsB.get(field) or "",
                    "Difference Type": "Mismatch",
                    "Impact": "Branding Drift",
                    "Recommended Action": f"Align {label.lower()} for brand '{name}'",
                    "Priority": "🟠 Medium"
                })
            else:
                matches.append({
                    "Category": "Brand Settings",
                    "Object": name,
                    "Attribute": label,
                    "Value": settingsA.get(field) or ""
                })

    for name in dictB:
        if name not in dictA:
            diffs.append({
                "Category": "Brand Settings",
                "Object": name,
                "Attribute": "-",
                "Env A Value": "Missing",
                "Env B Value": "Exists",
                "Difference Type": "Extra in Env B",
                "Impact": "Unexpected Brand",
                "Recommended Action": f"Review extra brand '{name}' in Env B",
                "Priority": "🟡 Low"
            })

    return diffs, matches
