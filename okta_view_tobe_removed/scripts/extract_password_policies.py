import requests
import csv
import configparser

# Define global variables
global okta_api_token
global okta_domain_url

# Load variables from config file
config = configparser.ConfigParser()
config.read('config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')


def get_password_policies():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = okta_domain_url + '/api/v1/policies?type=PASSWORD'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print("Error fetching password policies: ", response.status_code)
        return []


def get_policy_rules(policy_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_url}/api/v1/policies/{policy_id}/rules"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(
            f"Error fetching rules for policy {policy_id}: ", response.status_code)
        return []


def extract_complexity_settings(policy):
    settings = policy.get('settings', {}).get('complexity', {})
    return ", ".join([f"{k}: {v}" for k, v in settings.items()])


def extract_lockout_settings(policy):
    settings = policy.get('settings', {}).get('lockout', {})
    return ", ".join([f"{k}: {v}" for k, v in settings.items()])

def export_password_policies_rules_to_csv(policies, output_file):
    fieldnames = [
        'policy_id',
        'policy_name',
        'rule_id',
        'rule_name',
        'status',
        'priority',
        'conditions_people',
        'conditions_network',
        'actions'
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for policy in policies:
            policy_id = policy['id']
            policy_name = policy['name']
            rules = get_policy_rules(policy_id)

            for rule in rules:
                writer.writerow({
                    'policy_id': policy_id,
                    'policy_name': policy_name,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'status': rule['status'],
                    'priority': rule.get('priority', ''),
                    'conditions_people': rule.get('conditions', {}).get('people', {}),
                    'conditions_network': rule.get('conditions', {}).get('network', {}),
                    'actions': rule.get('actions', {})
                })


def export_password_policies_to_csv(policies, output_file):
    fieldnames = [
        'ID',
        'Status',
        'Name',
        'Description',
        'Priority',
        'Provider',
        'Complexity Settings',
        'Lockout Settings',
        'Rules'
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for policy in policies:
            policy_id = policy['id']
            rules = get_policy_rules(policy_id)

            writer.writerow({
                'ID': policy_id,
                'Status': policy['status'],
                'Name': policy['name'],
                'Description': policy.get('description', ''),
                'Priority': policy['priority'],
                'Provider': policy.get('provider', {}).get('type', ''),
                'Complexity Settings': extract_complexity_settings(policy),
                'Lockout Settings': extract_lockout_settings(policy),
                'Rules': ", ".join([rule['name'] for rule in rules])
            })


def extract_password_policies(csv_output_file_password_policies):
    policies = get_password_policies()

    if policies:
        export_password_policies_to_csv(
            policies, csv_output_file_password_policies)
        csv_output_file_password_policies_rules = csv_output_file_password_policies.replace(".csv", "_rules.csv")
        export_password_policies_rules_to_csv(policies, csv_output_file_password_policies_rules)
