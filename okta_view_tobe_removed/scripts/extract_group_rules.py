import requests
import csv
import configparser

# Define global variables
global okta_api_token
global okta_domain_url

# Load variables from config file
config = configparser.ConfigParser()
#config.read('../config.ini')
config.read('config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')

def get_groups_map():
    """Fetch all groups and create a mapping of group IDs to group names."""
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    groups_map = {}
    url = okta_domain_url + '/api/v1/groups'
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            for group in response_json:
                groups_map[group['id']] = group['profile']['name']

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error fetching groups: ", response.status_code)
            break

    return groups_map


def get_group_rules():
    """Fetch all group rules."""
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    group_rules = []
    url = okta_domain_url + '/api/v1/groups/rules'
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            group_rules.extend(response_json)

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error fetching group rules: ", response.status_code)
            break

    return group_rules


def export_group_rules_to_csv(group_rules, groups_map, output_file):
    """Export group rules to a CSV file."""
    fieldnames = [
        'Rule ID',
        'Rule Name',
        'Status',
        'Conditions',
        'Actions',
        'Created At',
        'Last Updated At',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for rule in group_rules:
            conditions = rule.get('conditions', {}).get('expression', {}).get('value', '')
            # Replace group IDs with group names in conditions
            for group_id, group_name in groups_map.items():
                conditions = conditions.replace(group_id, group_name)

            row = {
                'Rule ID': rule.get('id', ''),
                'Rule Name': rule.get('name', ''),
                'Status': rule.get('status', ''),
                'Conditions': conditions,
                'Actions': rule.get('actions', {}),
                'Created At': rule.get('created', ''),
                'Last Updated At': rule.get('lastUpdated', ''),
            }
            writer.writerow(row)


def extract_group_rules(csv_output_file_group_rules):
    """Main function to extract group rules."""
    groups_map = get_groups_map()
    group_rules = get_group_rules()

    if group_rules:
        export_group_rules_to_csv(group_rules, groups_map, csv_output_file_group_rules)


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityGroupRules.csv'
    extract_group_rules(output_file)