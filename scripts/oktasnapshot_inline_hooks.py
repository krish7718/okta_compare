import json
import logging

from scripts.extract_inline_hooks import get_inline_hooks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_inline_hooks_view(domain_url, api_token):
    logger.info("Fetching inline hooks for OktaView.")
    hooks = get_inline_hooks(domain_url, api_token) or []
    rows = []
    for hook in hooks:
        channel = hook.get("channel") or {}
        config = channel.get("config") or {}
        rows.append({
            "Inline Hook ID": hook.get("id"),
            "Name": hook.get("name"),
            "Type": hook.get("type"),
            "Version": hook.get("version"),
            "Status": hook.get("status"),
            "Created": hook.get("created"),
            "Last Updated": hook.get("lastUpdated"),
            "Channel Type": channel.get("type"),
            "Endpoint URI": config.get("uri"),
            "Method": config.get("method"),
            "Auth Scheme": (config.get("authScheme") or {}).get("type"),
            "Headers": json.dumps(config.get("headers") or [], sort_keys=True, default=str),
        })
    return rows
