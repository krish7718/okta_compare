import logging

from scripts.extract_brands import get_brands, get_brand_pages

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_brand_pages_view(domain_url, api_token):
    logger.info("Fetching brand pages for OktaView.")
    brands = get_brands(domain_url, api_token) or []
    rows = []
    for brand in brands:
        brand_id = brand.get("id")
        brand_name = brand.get("name")
        pages = get_brand_pages(domain_url, api_token, brand_id) or {}
        sign_in = pages.get("sign_in") or {}
        error_page = pages.get("error") or {}

        rows.append({
            "Brand Name": brand_name,
            "Page Type": "Sign-In",
            "Page Content": sign_in.get("pageContent") or sign_in.get("htmlContent"),
            "Widget Version": sign_in.get("widgetVersion"),
            "Widget Customizations": sign_in.get("widgetCustomizations"),
        })
        rows.append({
            "Brand Name": brand_name,
            "Page Type": "Error",
            "Page Content": error_page.get("pageContent") or error_page.get("htmlContent"),
            "Widget Version": error_page.get("widgetVersion"),
            "Widget Customizations": error_page.get("widgetCustomizations"),
        })
    return rows
