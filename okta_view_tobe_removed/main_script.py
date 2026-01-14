import configparser
import os
import subprocess
import shutil
import scripts.extract_applications as extract_applications
import scripts.extract_network_zones as extract_network_zones
import scripts.extract_identity_providers as extract_identity_providers
import scripts.extract_org_settings as extract_org_settings
import scripts.extract_password_policies as extract_password_policies
import scripts.extract_authorization_servers as extract_authorization_servers
import scripts.extract_security_settings as extract_security_settings
import scripts.extract_global_session_policies as extract_global_session_policies
import scripts.extract_authentication_policies as extract_authentication_policies
import scripts.extract_mfa_enroll_policies as extract_mfa_enroll_policies
import scripts.extract_group_rules as extract_group_rules
import generate_guide as generate_guide


def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def main():
    config_file = "config.ini"
    config = load_config(config_file)

    okta_domain_url = config.get('okta', 'okta_domain_url')
    csv_output_file_applications = config.get(
        'csv_files', 'csv_output_file_applications')

    csv_output_file_network_zones = config.get(
        'csv_files', 'csv_output_file_network_zones')

    csv_output_file_identity_providers = config.get(
        'csv_files', 'csv_output_file_identity_providers')

    csv_output_file_org_settings = config.get(
        'csv_files', 'csv_output_file_org_settings')

    csv_output_file_password_policies = config.get(
        'csv_files', 'csv_output_file_password_policies')
    
    csv_output_file_global_session_policies = config.get(
        'csv_files', 'csv_output_file_global_session_policies')

    csv_output_file_authentication_policies = config.get(
        'csv_files', 'csv_output_file_authentication_policies')
    
    csv_output_file_mfa_enroll_policies = config.get(
        'csv_files', 'csv_output_file_mfa_enroll_policies')

    csv_output_file_authorization_servers = config.get(
        'csv_files', 'csv_output_file_authorization_servers')
    
    csv_output_file_org_security_settings = config.get(
        'csv_files', 'csv_output_file_org_security_settings')
    
    csv_output_file_group_rules = config.get(
        'csv_files', 'csv_output_file_group_rules')


    print("Okta Domain URL : "+okta_domain_url)
    print("Extracting Organization Information .......")
    extract_org_settings.extract_organization_information(
        csv_output_file_org_settings)
    
    print("Extracting Network Zones .......")
    extract_network_zones.extract_network_zones(csv_output_file_network_zones)
    
    print("Extracting Identity Providers .......")
    extract_identity_providers.extract_identity_providers(
        csv_output_file_identity_providers)
    
    print("Extracting Password Policies .......")
    extract_password_policies.extract_password_policies(
        csv_output_file_password_policies)
    
    print("Extracting Global Session Policies .......")
    extract_global_session_policies.extract_global_session_policies(
        csv_output_file_global_session_policies)
    
    print("Extracting Authentication Policies .......")
    extract_authentication_policies.extract_authentication_policies(
        csv_output_file_authentication_policies)

    print("Extracting MFA Enrollment Policies .......")
    extract_mfa_enroll_policies.extract_mfa_policies(
        csv_output_file_mfa_enroll_policies)
    
    print("Extracting Authorizing Servers .......")
    extract_authorization_servers.extract_authorization_servers(
        csv_output_file_authorization_servers)
    
    print("Extracting Applications .......")
    extract_applications.extract_applications(csv_output_file_applications)
    
    print("Extracting Organization Security Settings .......")
    extract_security_settings.extract_security_settings(csv_output_file_org_security_settings)

    print("Extracting Group Rules .......")
    extract_group_rules.extract_group_rules(csv_output_file_group_rules)

def display_startup_banner():
    tool_name = "Okta View"
    padding = 40
    box_width = len(tool_name) + padding
    terminal_width = shutil.get_terminal_size().columns
    border = "*" * (box_width + 2)

    # ANSI color codes for styling
    COLOR_CYAN = "\033[96m"
    COLOR_RESET = "\033[0m"

    # Prepare banner lines
    line1 = border
    line2 = "*" + " " * ((box_width - len(tool_name)) // 2) + tool_name + " " * ((box_width - len(tool_name) + 1) // 2) + "*"
    line3 = border

    # Center each line based on terminal width and apply color
    for line in [line1, line2, line3]:
        print(COLOR_CYAN + line.center(terminal_width) + COLOR_RESET)

if __name__ == "__main__":
    display_startup_banner()
    main()
    subprocess.run(["/usr/local/bin/python3", "generate_guide.py", "--debug"])
