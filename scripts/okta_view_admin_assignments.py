import logging

from scripts.extract_admin_roles import get_admin_users, get_admin_groups, get_admin_apps

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("okta_compare")


def get_admin_assignments_view(domain_url, api_token):
    logger.info("Fetching admin assignments for OktaView.")
    users = get_admin_users(domain_url, api_token) or []
    groups = get_admin_groups(domain_url, api_token) or []
    apps = get_admin_apps(domain_url, api_token) or []

    user_rows = []
    for user in users:
        user_rows.append({
            "User ID": user.get("userId"),
            "Display Name": user.get("displayName"),
            "Email": user.get("email"),
            "Login": user.get("login"),
        })

    group_rows = []
    for group in groups:
        group_rows.append({
            "Group ID": group.get("groupId"),
            "Group Name": group.get("name"),
        })

    app_rows = []
    for app in apps:
        app_rows.append({
            "Client ID": app.get("clientId"),
            "Display Name": app.get("displayName"),
            "App Name": app.get("appName"),
            "App Instance ID": app.get("appInstanceId"),
        })

    return user_rows, group_rows, app_rows
