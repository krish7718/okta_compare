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


def get_brands():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    brands = []
    url = okta_domain_url + '/api/v1/brands'
    while url:
        print(f"Requesting URL: {url}")  # Debugging
        response = requests.get(url, headers=headers)
        print(f"Response Status Code: {response.status_code}")  # Debugging
        print(f"Response Body: {response.text}")  # Debugging

        if response.status_code == 200:
            response_json = response.json()
            brands.extend(response_json)  # Directly extend the list of brands

            # Handle pagination using the Link header
            next_link = response.headers.get('Link')
            if next_link and 'rel="next"' in next_link:
                url = next_link.split(';')[0].strip('<>')
            else:
                url = None
        else:
            print("Error: ", response.status_code)
            break

    return brands


def export_brands_to_csv(brands, output_file):
    fieldnames = [
        'Brand ID',
        'Name',
        'Custom Domain',
        'Created At',
        'Last Updated At',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for brand in brands:
            row = {
                'Brand ID': brand.get('id', ''),
                'Name': brand.get('name', ''),
                'Custom Domain': brand.get('customDomain', ''),
                'Created At': brand.get('created', ''),
                'Last Updated At': brand.get('lastUpdated', ''),
            }
            writer.writerow(row)


def extract_brands(csv_output_file_brands):
    brands = get_brands()

    if brands:
        export_brands_to_csv(brands, csv_output_file_brands)


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityBrands.csv'
    extract_brands(output_file)