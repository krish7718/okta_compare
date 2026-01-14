import logging

from scripts.extract_brands import get_brands, get_brand_themes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def _pick_theme(themes):
    if not themes:
        return {}
    for theme in themes:
        if theme.get("isDefault"):
            return theme
    return themes[0]


def get_brand_settings_view(domain_url, api_token):
    logger.info("Fetching brand settings for OktaView.")
    brands = get_brands(domain_url, api_token) or []
    rows = []
    for brand in brands:
        brand_id = brand.get("id")
        themes = get_brand_themes(domain_url, api_token, brand_id) or []
        theme = _pick_theme(themes) or {}
        rows.append({
            "Brand Name": brand.get("name"),
            "Remove Powered By Okta": brand.get("removePoweredByOkta"),
            "Custom Privacy Policy URL": brand.get("customPrivacyPolicyUrl"),
            "Agree To Custom Privacy Policy": brand.get("agreeToCustomPrivacyPolicy"),
            "Is Default": brand.get("isDefault"),
            "Logo": theme.get("logo"),
            "Favicon": theme.get("favicon"),
            "Background Image": theme.get("backgroundImage"),
            "Primary Color Hex": theme.get("primaryColorHex"),
            "Primary Color Contrast Hex": theme.get("primaryColorContrastHex"),
            "Secondary Color Hex": theme.get("secondaryColorHex"),
            "Secondary Color Contrast Hex": theme.get("secondaryColorContrastHex"),
            "Sign-In Page Variant": theme.get("signInPageTouchPointVariant"),
            "Error Page Variant": theme.get("errorPageTouchPointVariant"),
            "Loading Page Variant": theme.get("loadingPageTouchPointVariant"),
            "Email Template Variant": theme.get("emailTemplateTouchPointVariant"),
            "End User Dashboard Variant": theme.get("endUserDashboardTouchPointVariant"),
        })
    return rows
