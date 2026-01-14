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


def get_identity_providers():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = okta_domain_url + '/api/v1/idps'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print("Error: ", response.status_code)
        return []


def extract_identity_provider_details(idp):
    details = {
        'name': idp.get('name'),
        'type': idp.get('type'),
        'protocol_type': idp.get('protocol', {}).get('type'),
        'protocol_endpoints_sso_url': idp.get('protocol', {}).get('endpoints', {}).get('sso', {}).get('url'),
        'protocol_credentials_trust_issuer': idp.get('protocol', {}).get('credentials', {}).get('trust', {}).get('issuer'),
        'protocol_credentials_trust_audience': idp.get('protocol', {}).get('credentials', {}).get('trust', {}).get('audience'),
        'protocol_credentials_signing_kid': idp.get('protocol', {}).get('credentials', {}).get('signing', {}).get('kid'),
        'status': idp.get('status'),
        'policy_maxClockSkew': idp.get('policy', {}).get('maxClockSkew'),
        'policy_accountLink_action': idp.get('policy', {}).get('accountLink', {}).get('action'),
        'policy_subject_userNameTemplate_template': idp.get('policy', {}).get('subject', {}).get('userNameTemplate', {}).get('template'),
        'policy_provisioning_action': idp.get('policy', {}).get('provisioning', {}).get('action'),
    }
    return details


def export_identity_providers_to_csv(idps, output_file):
    fieldnames = [
        'name',
        'type',
        'protocol_type',
        'protocol_endpoints_sso_url',
        'protocol_credentials_trust_issuer',
        'protocol_credentials_trust_audience',
        'protocol_credentials_signing_kid',
        'status',
        'policy_maxClockSkew',
        'policy_accountLink_action',
        'policy_subject_userNameTemplate_template',
        'policy_provisioning_action',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for idp in idps:
            details = extract_identity_provider_details(idp)
            writer.writerow(details)


def extract_identity_providers(csv_output_file_identity_providers):
    idps = get_identity_providers()

    if idps is not None:
        export_identity_providers_to_csv(
            idps, csv_output_file_identity_providers)
