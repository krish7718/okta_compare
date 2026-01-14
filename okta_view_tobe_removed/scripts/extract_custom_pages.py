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

def get_custom_sign_in_pages():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    custom_sign_in_pages = []
    url = okta_domain_url + '/api/v1/pages/sign-in'
    print(f"Requesting URL: {url}")  # Debugging
    response = requests.get(url, headers=headers)
    print(f"Response Status Code: {response.status_code}")  # Debugging
    print(f"Response Body: {response.text}")  # Debugging

    if response.status_code == 200:
        response_json = response.json()
        custom_sign_in_pages.extend(response_json.get('pages', []))  # Extract pages from the response
    elif response.status_code == 405:
        print("Sign-In Pages endpoint does not support GET method. Please verify feature availability.")
    else:
        print(f"Error fetching sign-in pages: {response.status_code}")

    return custom_sign_in_pages


def get_custom_error_pages(brand_ids):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    custom_error_pages = []
    for brand_id in brand_ids:
        url = f"{okta_domain_url}/api/v1/brands/{brand_id}/pages/error/customized"
        print(f"Requesting URL: {url}")  # Debugging
        response = requests.get(url, headers=headers)
        print(f"Response Status Code: {response.status_code}")  # Debugging
        print(f"Response Body: {response.text}")  # Debugging

        if response.status_code == 200:
            response_json = response.json()
            custom_error_pages.append({
                'Page ID': None,  # Error pages don't have a page ID
                'Domain': None,  # Error pages are not tied to a specific domain
                'Type': 'ERROR_PAGE',
                'HTML Content': response_json.get('htmlContent', ''),
                'Created At': response_json.get('created', ''),
                'Last Updated At': response_json.get('lastUpdated', ''),
                'Brand ID': brand_id,
            })
        elif response.status_code == 404:
            print(f"No custom error page found for brand {brand_id}. Skipping...")
        else:
            print(f"Error fetching custom error page for brand {brand_id}: {response.status_code}")

    return custom_error_pages


def export_custom_pages_to_csv(custom_pages, output_file):
    fieldnames = [
        'Page ID',
        'Domain',
        'Type',
        'HTML Content',
        'Created At',
        'Last Updated At',
        'Brand ID',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for page in custom_pages:
            writer.writerow(page)


def extract_custom_sign_in_pages():
    custom_sign_in_pages = get_custom_sign_in_pages()

    formatted_pages = [
        {
            'Page ID': page.get('id', ''),
            'Domain': page.get('domain', ''),
            'Type': 'SIGN_IN_PAGE',
            'HTML Content': page.get('htmlContent', ''),
            'Created At': page.get('created', ''),
            'Last Updated At': page.get('lastUpdated', ''),
            'Brand ID': None,  # Sign-in pages are not tied to a specific brand
        }
        for page in custom_sign_in_pages
    ]

    return formatted_pages


def extract_custom_error_pages():
    # Fetch all brand IDs
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = f"{okta_domain_url}/api/v1/brands"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        brand_ids = [brand['id'] for brand in response.json()]
        return get_custom_error_pages(brand_ids)
    else:
        print("Error fetching brands: ", response.status_code)
        return []


if __name__ == "__main__":
    output_file = '../config_csv_files/configEntityCustomPages.csv'

    sign_in_pages = extract_custom_sign_in_pages()
    error_pages = extract_custom_error_pages()

    all_pages = sign_in_pages + error_pages
    export_custom_pages_to_csv(all_pages, output_file)