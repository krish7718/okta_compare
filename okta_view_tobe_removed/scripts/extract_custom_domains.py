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

def get_custom_domains():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    custom_domains = []
    url = okta_domain_url + '/api/v1/domains'
    while url:
        print(f"Requesting URL: {url}")  # Debugging
        response = requests.get(url, headers=headers)
        print(f"Response Status Code: {response.status_code}")  # Debugging
        print(f"Response Body: {response.text}")  # Debugging

        if response.status_code == 200:
            response_json = response.json()
            custom_domains.extend(response_json.get('domains', []))  # Extract domains from the response

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error: ", response.status_code)
            break

    return custom_domains


def export_custom_domains_to_csv(custom_domains, output_file):
    fieldnames = [
        'Domain ID',
        'Domain Name',
        'Certificate Type',
        'Certificate Source Type',
        'Status',
        'Created At',
        'Last Updated At',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for domain in custom_domains:
            row = {
                'Domain ID': domain.get('id', ''),
                'Domain Name': domain.get('domain', ''),
                'Certificate Type': domain.get('certificateType', ''),
                'Certificate Source Type': domain.get('certificateSourceType', ''),
                'Status': domain.get('status', ''),
                'Created At': domain.get('created', ''),
                'Last Updated At': domain.get('lastUpdated', ''),
            }
            writer.writerow(row)


def extract_custom_domains(csv_output_file_custom_domains):
    custom_domains = get_custom_domains()

    if custom_domains:
        export_custom_domains_to_csv(custom_domains, csv_output_file_custom_domains)


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityCustomDomains.csv'
    extract_custom_domains(output_file)