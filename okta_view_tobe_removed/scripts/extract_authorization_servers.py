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


def get_authorization_servers():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = okta_domain_url + '/api/v1/authorizationServers'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return []


def extract_authorization_server_data(authorization_server):
    data = {
        'ID': authorization_server['id'],
        'Name': authorization_server['name'],
        'Status': authorization_server['status'],
        'Description': authorization_server['description'],
        'Audiences': ', '.join(authorization_server['audiences']),
        'Issuer': authorization_server['issuer'],
        'Credentials Rotation Mode': authorization_server['credentials']['signing']['rotationMode']
    }
    return data


# def get_claims(authorization_server_id):
#     headers = {
#         'Authorization': f"SSWS {okta_api_token}",
#         'Accept': 'application/json'
#     }

#     url = f"{okta_domain_url}/api/v1/authorizationServers/{authorization_server_id}/claims"

#     response = requests.get(url, headers=headers)

#     if response.status_code == 200:
#         return [claim['name'] for claim in response.json()]
#     else:
#         print(
#             f"Error: {response.status_code} fetching claims for authorization server {authorization_server_id}")
#         return []


def export_authorizarion_servers_to_csv(authorization_server_data, output_file):
    fieldnames = ['ID', 'Name', 'Status', 'Description', 'Audiences',
                  'Issuer', 'Credentials Rotation Mode']

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for server_data in authorization_server_data:
            writer.writerow(extract_authorization_server_data(server_data))


def extract_authorization_servers(csv_output_file_authorization_servers):
    authorization_servers = get_authorization_servers()

    if authorization_servers:
        export_authorizarion_servers_to_csv(
            authorization_servers, csv_output_file_authorization_servers)
