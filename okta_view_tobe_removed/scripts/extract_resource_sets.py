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
okta_domain_url = config.get('okta', 'okta_domain_url').rstrip('/')


def get_resource_set_details(resource_set_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    # Fetch resource set details
    url = okta_domain_url + f'/api/v1/iam/resource-sets/{resource_set_id}'
    print(f"Requesting Resource Set Details URL: {url}")  # Debugging
    response = requests.get(url, headers=headers)
    print(f"Response Status Code: {response.status_code}")  # Debugging
    print(f"Response Body: {response.text}")  # Debugging

    if response.status_code == 200:
        resource_set_details = response.json()

        # Fetch resources from the /resources endpoint
        resources_url = okta_domain_url + f'/api/v1/iam/resource-sets/{resource_set_id}/resources'
        resources = []
        print(f"Requesting Resources URL: {resources_url}")  # Debugging
        resources_response = requests.get(resources_url, headers=headers)
        print(f"Resources Response Status Code: {resources_response.status_code}")  # Debugging
        print(f"Resources Response Body: {resources_response.text}")  # Debugging
        if resources_response.status_code == 200:
            resources = resources_response.json()

        # Add resources to the resource set details
        resource_set_details['resources'] = resources
        return resource_set_details
    else:
        print("Error: ", response.status_code)
        return {}


def get_resource_sets():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    resource_sets = []
    url = okta_domain_url + '/api/v1/iam/resource-sets'

    print(f"Requesting URL: {url}")  # Debugging
    response = requests.get(url, headers=headers)
    print(f"Response Status Code: {response.status_code}")  # Debugging
    print(f"Response Body: {response.text}")  # Debugging

    if response.status_code == 200:
        response_json = response.json()
        resource_sets = response_json.get('resource-sets', [])
    else:
        print("Error: ", response.status_code)

    return resource_sets


def export_resource_sets_to_csv(resource_sets, output_file):
    fieldnames = [
        'Resource Set Name',
        'Description',
        'Resource Set ID',
        'Resources',
        'Created By',
        'Created At',
        'Last Updated By',
        'Last Updated At',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for resource_set in resource_sets:
            # Extract resource set details
            resource_set_id = resource_set.get('id', '')
            resource_set_details = get_resource_set_details(resource_set_id)

            row = {
                'Resource Set Name': resource_set.get('label', ''),
                'Description': resource_set.get('description', ''),
                'Resource Set ID': resource_set_id,
                'Resources': resource_set_details.get('resources', []),
                'Created By': resource_set_details.get('createdBy', ''),
                'Created At': resource_set.get('created', ''),
                'Last Updated By': resource_set_details.get('lastUpdatedBy', ''),
                'Last Updated At': resource_set.get('lastUpdated', ''),
            }

            writer.writerow(row)


def extract_resource_sets(csv_output_file_resource_sets):
    resource_sets = get_resource_sets()

    if resource_sets:
        export_resource_sets_to_csv(resource_sets, csv_output_file_resource_sets)


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityResourceSets.csv'
    extract_resource_sets(output_file)
    print(f"Resource sets have been exported to {output_file}")