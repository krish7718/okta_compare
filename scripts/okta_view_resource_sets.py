import logging

from scripts.extract_admin_roles import get_resource_sets, get_resource_set_resources, get_resource_set_bindings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_resource_sets_view(domain_url, api_token):
    logger.info("Fetching resource sets for OktaView.")
    sets = get_resource_sets(domain_url, api_token) or []
    set_rows = []
    resource_rows = []
    binding_rows = []

    for resource_set in sets:
        set_id = resource_set.get("id")
        label = resource_set.get("label") or resource_set.get("name")
        set_rows.append({
            "Resource Set ID": set_id,
            "Label": label,
            "Description": resource_set.get("description"),
            "Created": resource_set.get("created"),
            "Last Updated": resource_set.get("lastUpdated"),
        })

        resources = get_resource_set_resources(domain_url, api_token, set_id) or []
        for resource in resources:
            resource_rows.append({
                "Resource Set": label,
                "Resource Type": resource.get("type"),
                "Resource ID": resource.get("id"),
                "Resource Name": resource.get("name"),
            })

        bindings = get_resource_set_bindings(domain_url, api_token, set_id) or []
        for binding in bindings:
            binding_rows.append({
                "Resource Set": label,
                "Binding ID": binding.get("id"),
                "Binding Label": binding.get("label"),
                "Role": binding.get("role"),
            })

    return set_rows, resource_rows, binding_rows
