import json
import logging

from scripts.extract_event_hooks import get_event_hooks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_event_hooks_view(domain_url, api_token):
    logger.info("Fetching event hooks for OktaView.")
    hooks = get_event_hooks(domain_url, api_token) or []
    rows = []
    for hook in hooks:
        channel = hook.get("channel") or {}
        config = channel.get("config") or {}
        rows.append({
            "Event Hook ID": hook.get("id"),
            "Name": hook.get("name"),
            "Description": hook.get("description"),
            "Status": hook.get("status"),
            "Verification Status": hook.get("verificationStatus"),
            "Created": hook.get("created"),
            "Last Updated": hook.get("lastUpdated"),
            "Channel Type": channel.get("type"),
            "Version": channel.get("version"),
            "Endpoint URI": config.get("uri"),
            "Method": config.get("method"),
            "Auth Scheme": (config.get("authScheme") or {}).get("type"),
            "Headers": json.dumps(config.get("headers") or [], sort_keys=True, default=str),
            "Events": json.dumps(hook.get("events") or {}, sort_keys=True, default=str),
        })
    return rows
