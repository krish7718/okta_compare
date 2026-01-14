import requests
import csv
import configparser

# Define global variables
global okta_api_token
global okta_domain_url

# Load variables from config file
config = configparser.ConfigParser()
config.read('../config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')

def get_groups():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    groups = []
    url = okta_domain_url + '/api/v1/groups'
    while url:
        print(f"Requesting URL: {url}")  # Debugging
        response = requests.get(url, headers=headers)
        print(f"Response Status Code: {response.status_code}")  # Debugging
        print(f"Response Body: {response.text}")  # Debugging

        if response.status_code == 200:
            response_json = response.json()
            groups.extend(response_json)

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error: ", response.status_code)
            break

    return groups


def export_groups_to_csv(groups, output_file):
    fieldnames = [
        'Group ID',
        'Group Name',
        'Description',
        'Type',
        'Created At',
        'Last Updated At',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for group in groups:
            row = {
                'Group ID': group.get('id', ''),
                'Group Name': group.get('profile', {}).get('name', ''),
                'Description': group.get('profile', {}).get('description', ''),
                'Type': group.get('type', ''),
                'Created At': group.get('created', ''),
                'Last Updated At': group.get('lastUpdated', ''),
            }
            writer.writerow(row)


def extract_groups(csv_output_file_groups):
    groups = get_groups()

    if groups:
        export_groups_to_csv(groups, csv_output_file_groups)

# def extract_applications(csv_output_file_applications):

#     apps = get_active_applications()

#     if apps is not None:
#         export_apps_to_csv(apps,
#                            csv_output_file_applications)

if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityGroups.csv'
    extract_groups(output_file)
