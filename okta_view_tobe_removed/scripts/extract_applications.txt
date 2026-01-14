import requests
import csv
import configparser
import os

# Define global variables
global okta_api_token
global okta_domain_url

# Load variables from config file
config = configparser.ConfigParser()
config.read('config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')


def get_active_applications():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    apps = []
    after = None

    while True:
        url = okta_domain_url+'/api/v1/apps?filter=status eq "ACTIVE"&limit=200'
        if after is not None:
            url += f'&after={after}'

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            new_apps = response.json()
            if new_apps:
                apps.extend(new_apps)
                after = new_apps[-1]['id']
            else:
                break
        else:
            print("Error: ", response.status_code)
            break

    return apps


def get_app_group_ids(app_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = okta_domain_url+f'/api/v1/apps/{app_id}/groups'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return [group['id'] for group in response.json()]
    else:
        print("Error: ", response.status_code)
        return []


def get_group_details(group_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = okta_domain_url+f'/api/v1/groups/{group_id}'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        group = response.json()
        return {
            'name': group['profile']['name'],
            'type': group['type'],
        }
    else:
        print("Error: ", response.status_code)
        return {}


def get_app_settings(app):
    signOnMode = app.get('signOnMode', '')
    settings = app.get('settings', {})
    app_settings = settings.get('app', {})

    if signOnMode == 'BOOKMARK':
        return app_settings.get('url', '')
    elif signOnMode == 'SAML_2_0':
        saml_settings = settings.get('signOn', {})
        return {
            'app': app_settings,
            'signOn': saml_settings
        }
    elif signOnMode == 'OPENID_CONNECT':
        oauth_settings = settings.get('oauthClient', {})
        return {
            'app': app_settings,
            'oauthClient': oauth_settings
        }
    else:
        return app_settings


def get_policy_name(policy_url):
    policy_id = policy_url.split('/')[-1]

    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = okta_domain_url+f'/api/v1/policies/{policy_id}'

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        policy = response.json()
        return policy.get('name', '')
    else:
        # Handle error case here
        print("Error: ", response.status_code)
        return ''


def export_apps_to_csv(apps, output_file):
    fieldnames = [
        'Application Name',
        'Okta Internal Name',
        'Application Type',
        'Username Format',
        'Logo',
        'Groups',
        'Application Settings',
        'Features',
        'Access Policy Name',
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for app in apps:
            # Extract the application username format
            credentials = app.get('credentials', {})
            userNameTemplate = credentials.get('userNameTemplate', {})
            application_username_format = userNameTemplate.get('template', '')

            # Extract the logo url
            links = app.get('_links', {})
            logo = links.get('logo', [{}])[0]
            logo_url = logo.get('href', '')

            # Get the groups for this app
            group_ids = get_app_group_ids(app['id'])
            groups = [get_group_details(group_id)
                      for group_id in group_ids]

            # Get the specific settings for this app
            app_settings = get_app_settings(app)

            # Get the features for this app
            features = app.get('features', [])

            # Get the access policy name for this app
            accessPolicy = links.get('accessPolicy', {})
            policy_name = get_policy_name(accessPolicy.get('href', ''))

            row = {
                'Application Name': app.get('label', ''),
                'Okta Internal Name': app.get('name', ''),
                'Application Type': app.get('signOnMode', ''),
                'Username Format': application_username_format,
                'Logo': logo_url,
                'Groups': groups,
                'Application Settings': app_settings,
                'Features': features,
                'Access Policy Name': policy_name,
            }

            writer.writerow(row)

            # Print the fieldnames and values
            # for fieldname in fieldnames:
            #     print(f"{fieldname}: {row[fieldname]}")


def extract_applications(csv_output_file_applications):

    apps = get_active_applications()

    if apps is not None:
        export_apps_to_csv(apps,
                           csv_output_file_applications)
