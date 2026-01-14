import requests
import csv
import configparser

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')
okta_domain_admin_url = config.get('okta', 'okta_domain_admin_url')

# Function to fetch internal org security notification settings
def get_internal_org_settings():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_admin_url}/api/internal/org/settings/security-notification-settings"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        #print("Successfully fetched security notification settings.")
        return response.json()
    else:
        print(f"Error fetching security notification settings: {response.status_code} - {response.text}")
        return {}

# Function to fetch ThreatInsight settings
def get_threatinsight_settings():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }

    url = f"{okta_domain_url}/api/v1/threats/configuration"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        #print("Successfully fetched ThreatInsight settings.")
        return response.json()
    else:
        print(f"Error fetching ThreatInsight settings: {response.status_code} - {response.text}")
        return {}

# Function to export security settings to a CSV file
def export_security_settings_to_csv(output_file):
    settings_data = []
    
    # Fetch security notification settings
    security_settings = get_internal_org_settings()
    if security_settings:
        print("Adding security notification settings to CSV.")
        settings_data.extend([
            {"Key": "New sign-on notification email", "Value": security_settings.get('sendEmailForNewDeviceEnabled', 'N/A')},
            {"Key": "Password changed notification email", "Value": security_settings.get('sendEmailForPasswordChangedEnabled', 'N/A')},
            {"Key": "Authenticator enrolled notification email", "Value": security_settings.get('sendEmailForFactorEnrollmentEnabled', 'N/A')},
            {"Key": "Authenticator reset notification email", "Value": security_settings.get('sendEmailForFactorResetEnabled', 'N/A')},
            {"Key": "Report suspicious activity via email", "Value": security_settings.get('reportSuspiciousActivityEnabled', 'N/A')}
        ])
    else:
        print("No security notification settings found.")
    
    # Fetch ThreatInsight settings
    threatinsight_settings = get_threatinsight_settings()

    # Even if ThreatInsight is not enabled, add the keys to the CSV with default values
    action = threatinsight_settings.get('action', 'N/A')
    exclude_zones_used = 'True' if threatinsight_settings.get('excludeZones') else 'False'
    #print("Adding ThreatInsight settings to CSV.")
    
    settings_data.extend([
        {"Key": "ThreatInsight Action", "Value": action},
        {"Key": "ThreatInsight Exclude Zones Used", "Value": exclude_zones_used}
    ])

    # Write to CSV
    print(f"Writing data to CSV file: {output_file}")
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Key', 'Value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(settings_data)
    
    #print("CSV file created successfully.")

# Function to extract security settings and save to a CSV
def extract_security_settings(csv_output_file):
    export_security_settings_to_csv(csv_output_file)
