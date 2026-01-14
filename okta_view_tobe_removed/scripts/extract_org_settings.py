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


def get_organization_billing_contact():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_url}/api/v1/org/contacts/billing"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        user_id = response.json().get('userId')
        if user_id:
            return get_user_email(user_id)

    else:
        print(f"Error: {response.status_code}")
        return None


def get_organization_technical_contact():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_url}/api/v1/org/contacts/technical"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        user_id = response.json().get('userId')
        if user_id:
            return get_user_email(user_id)

    else:
        print(f"Error: {response.status_code}")
        return None


def get_organization_information():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f'{okta_domain_url}/api/v1/org'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None


def get_user_email(user_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_url}/api/v1/users/{user_id}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json().get('email')
    else:
        print(
            f"Error: {response.status_code} while fetching user email for ID: {user_id}")
        return None


def extract_org_information_details(org_info):
    details = {
        'Address1': org_info.get('address1'),
        'Address2': org_info.get('address2'),
        'City': org_info.get('city'),
        'Company Name': org_info.get('companyName'),
        'Country': org_info.get('country'),
        'End User Support Help URL': org_info.get('endUserSupportHelpURL'),
        'Phone Number': org_info.get('phoneNumber'),
        'Postal Code': org_info.get('postalCode'),
        'State': org_info.get('state'),
        'Support Phone Number': org_info.get('supportPhoneNumber'),
        'Website': org_info.get('website'),
        'id': org_info.get('id'),
        'created': org_info.get('created'),
        'lastUpdated': org_info.get('lastUpdated'),
        'expiresAt': org_info.get('expiresAt'),
        'Status': org_info.get('status'),
        'Subdomain': org_info.get('subdomain'),
        'Billing Contact Email': get_organization_billing_contact(),
        'Technical Contact Email': get_organization_technical_contact()

    }
    return details


def export_org_information_to_csv(org_info, output_file):
    fieldnames = [
        'Address1',
        'Address2',
        'City',
        'Company Name',
        'Country',
        'End User Support Help URL',
        'Phone Number',
        'Postal Code',
        'State',
        'Support Phone Number',
        'Website',
        'id',
        'created',
        'lastUpdated',
        'expiresAt',
        'Status',
        'Subdomain',
        'Technical Contact Email',
        'Billing Contact Email'
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        writer.writerow(extract_org_information_details(org_info))


def extract_organization_information(csv_output_file_organization_information):
    org_info = get_organization_information()

    if org_info is not None:
        export_org_information_to_csv(
            org_info, csv_output_file_organization_information)
