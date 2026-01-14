import requests
import csv
import configparser
import os

# Define global variables
global okta_api_token
global okta_domain_url

# Load variables from config file
config = configparser.ConfigParser()
config.read('../config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')

def get_admin_roles():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    admin_roles = []
    url = okta_domain_url + '/api/v1/iam/roles'  # Updated endpoint
    while url:
        print(f"Requesting URL: {url}")  # Debugging
        response = requests.get(url, headers=headers)
        print(f"Response Status Code: {response.status_code}")  # Debugging
        print(f"Response Body: {response.text}")  # Debugging

        if response.status_code == 200:
            response_json = response.json()

            # Check if the response is a list or a dictionary
            if isinstance(response_json, list):
                admin_roles.extend(response_json)  # Extend the list with roles from the response
            elif isinstance(response_json, dict) and 'roles' in response_json:
                admin_roles.extend(response_json['roles'])  # Extract roles from the 'roles' key
            else:
                print("Unexpected response format:", response_json)
                break

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error: ", response.status_code)
            break

    return admin_roles


def export_admin_roles_to_csv(admin_roles, output_file):
    fieldnames = [
        'Role ID',
        'Label',
        'Description',
        'Status',
        'Created At',
        'Last Updated At',
    ]

    os.makedirs(os.path.dirname(output_file), exist_ok=True)  # Ensure directory exists

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for role in admin_roles:
            row = {
                'Role ID': role.get('id', ''),
                'Label': role.get('label', ''),
                'Description': role.get('description', ''),
                'Status': role.get('status', ''),
                'Created At': role.get('created', ''),
                'Last Updated At': role.get('lastUpdated', ''),
            }
            writer.writerow(row)


def extract_admin_roles(csv_output_file_admin_roles):
    admin_roles = get_admin_roles()

    if admin_roles:
        export_admin_roles_to_csv(admin_roles, csv_output_file_admin_roles)


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityAdminRoles.csv'
    extract_admin_roles(output_file)
    print(f"Admin roles have been exported to {output_file}")