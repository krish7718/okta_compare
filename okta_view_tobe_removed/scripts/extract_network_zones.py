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


def get_network_zones():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = okta_domain_url + '/api/v1/zones'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print("Error: ", response.status_code)
        return []


def extract_gateway_values(zone):

    gateways = zone.get('gateways', [])
    if gateways:
        return [gateway['value'] for gateway in gateways]
    else:
        return ""


def extract_proxies_values(zone):

    proxies = zone.get('proxies', [])
    if proxies:
        return [proxy['value'] for proxy in proxies]
    else:
        return ""


def export_network_zones_to_csv(zones, output_file):
    fieldnames = [
        'Name',
        'Status',
        'Gateways',
        'Proxies',
        'Usage'
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for zone in zones:
            writer.writerow({
                'Name': zone['name'],
                'Status': zone['status'],
                'Gateways': extract_gateway_values(zone),
                'Proxies': extract_proxies_values(zone),
                'Usage': zone['usage']
            })


def extract_network_zones(csv_output_file_network_zones):
    zones = get_network_zones()

    if zones is not None:
        export_network_zones_to_csv(zones, csv_output_file_network_zones)
