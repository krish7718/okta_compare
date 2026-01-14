import logging

from scripts.extract_group_rules import get_groups_map, get_group_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_group_rules_view(domain_url, api_token):
    logger.info("Fetching group rules for OktaView.")
    groups_map = get_groups_map(domain_url, api_token) or {}
    rules = get_group_rules(domain_url, api_token) or []
    rows = []
    for rule in rules:
        conditions = rule.get("conditions", {}).get("expression", {}).get("value", "") or ""
        for group_id, group_name in groups_map.items():
            conditions = conditions.replace(group_id, group_name)
        actions = rule.get("actions", {}) or {}
        assign_groups = (actions.get("assignUserToGroups", {}) or {}).get("groupIds") or []
        assign_names = [groups_map.get(gid, gid) for gid in assign_groups]
        then_text = f"Assign to {', '.join(assign_names)}" if assign_names else ""

        except_parts = []
        people_exclude = (rule.get("conditions", {}) or {}).get("people", {}).get("exclude", {}) or {}
        exclude_group_ids = people_exclude.get("groupIds") or []
        exclude_user_ids = people_exclude.get("userIds") or []
        if exclude_group_ids:
            exclude_groups = [groups_map.get(gid, gid) for gid in exclude_group_ids]
            except_parts.append(f"Groups: {', '.join(exclude_groups)}")
        if exclude_user_ids:
            except_parts.append(f"Users: {', '.join(exclude_user_ids)}")
        except_text = "; ".join(except_parts)

        rows.append({
            "Rule Name": rule.get("name"),
            "Status": rule.get("status"),
            "If": conditions,
            "Then": then_text,
            "Except": except_text,
        })
    return rows
